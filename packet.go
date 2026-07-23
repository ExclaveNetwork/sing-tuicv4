package tuicv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

var udpMessagePool = sync.Pool{
	New: func() any {
		return new(udpMessage)
	},
}

func allocMessage() *udpMessage {
	message := udpMessagePool.Get().(*udpMessage)
	message.referenced = true
	return message
}

type udpMessage struct {
	sessionID   uint32
	destination M.Socksaddr
	data        *buf.Buffer
	referenced  bool
}

func (m *udpMessage) release() {
	if !m.referenced {
		return
	}
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *udpMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		buffer.WriteByte(Version),
		buffer.WriteByte(CommandPacket),
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, uint16(m.data.Len())),
		AddressSerializer.WriteAddrPort(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 8 + AddressSerializer.AddrPortLen(m.destination)
}

var (
	_ N.NetPacketConn    = (*udpPacketConn)(nil)
	_ N.PacketReadWaiter = (*udpPacketConn)(nil)
)

type udpPacketConn struct {
	ctx             context.Context
	cancel          common.ContextCancelCauseFunc
	sessionID       uint32
	quicConn        *quic.Conn
	data            chan *udpMessage
	udpStream       bool
	closeOnce       sync.Once
	isServer        bool
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	writeDeadline   pipe.Deadline
}

func newUDPPacketConn(ctx context.Context, quicConn *quic.Conn, udpStream bool, isServer bool, onDestroy func()) *udpPacketConn {
	ctx, cancel := common.ContextWithCancelCause(ctx)
	return &udpPacketConn{
		ctx:           ctx,
		cancel:        cancel,
		quicConn:      quicConn,
		data:          make(chan *udpMessage, 64),
		udpStream:     udpStream,
		isServer:      isServer,
		onDestroy:     onDestroy,
		readDeadline:  pipe.MakeDeadline(),
		writeDeadline: pipe.MakeDeadline(),
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = p.destination
		p.releaseMessage()
		return destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		n = copy(p, pkt.data.Bytes())
		if pkt.destination.IsDomain() {
			addr = pkt.destination
		} else {
			addr = pkt.destination.UDPAddr()
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	case <-c.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	if buffer.Len() > 0xffff {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	if !destination.IsValid() {
		return E.New("invalid destination address")
	}
	message := allocMessage()
	*message = udpMessage{
		sessionID:   c.sessionID,
		destination: destination,
		data:        buffer,
	}
	err := c.writePacket(message)
	message.releaseMessage()
	return err
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(p) > 0xffff {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 0xffff}
	}
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		return 0, E.New("invalid destination address")
	}
	message := allocMessage()
	*message = udpMessage{
		sessionID:   c.sessionID,
		destination: destination,
		data:        buf.As(p),
	}
	err = c.writePacket(message)
	message.releaseMessage()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpPacketConn) inputPacket(message *udpMessage) {
	select {
	case c.data <- message:
	default:
		message.releaseMessage()
	}
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	if !c.udpStream {
		buffer := message.pack()
		err := c.quicConn.SendDatagram(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return err
		}
	} else {
		stream, err := c.quicConn.OpenUniStream()
		if err != nil {
			return err
		}
		stopWatch := context.AfterFunc(c.ctx, func() {
			_ = stream.SetWriteDeadline(time.Now())
		})
		buffer := message.pack()
		_, err = stream.Write(buffer.Bytes())
		buffer.Release()
		stream.Close()
		stopWatch()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
	if !c.isServer {
		buffer := buf.NewSize(6)
		defer buffer.Release()
		common.Must(buffer.WriteByte(Version))
		common.Must(buffer.WriteByte(CommandDissociate))
		common.Must(binary.Write(buffer, binary.BigEndian, c.sessionID))
		sendStream, openErr := c.quicConn.OpenUniStream()
		if openErr != nil {
			return
		}
		sendStream.Write(buffer.Bytes())
		sendStream.Close()
	}
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

func readUDPMessage(message *udpMessage, reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	message.data = buf.NewSize(int(dataLength))
	_, err = message.data.ReadFullFrom(reader, message.data.FreeLen())
	if err != nil {
		return err
	}
	return nil
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	var dataLength uint16
	err = binary.Read(reader, binary.BigEndian, &dataLength)
	if err != nil {
		return err
	}
	message.destination, err = AddressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	if reader.Len() != int(dataLength) {
		return io.ErrUnexpectedEOF
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
