package tuicv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"lukechampine.com/blake3"
)

type ServiceOptions struct {
	Context           context.Context
	Logger            logger.Logger
	TLSConfig         aTLS.ServerConfig
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
	UDPMTU            int
	Handler           ServiceHandler

	allowAllCongestionControl bool // do not export
}

type ServiceHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx               context.Context
	logger            logger.Logger
	tlsConfig         aTLS.ServerConfig
	quicConfig        *quic.Config
	userMap           map[[32]byte]U
	congestionControl string
	authTimeout       time.Duration
	udpTimeout        time.Duration
	udpMTU            int
	handler           ServiceHandler

	quicListener io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               options.ZeroRTTHandshake,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
		DisablePathManager:      true,
	}
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr", "bbr2":
	default:
		if !options.allowAllCongestionControl {
			return nil, E.New("unknown congestion control algorithm: ", options.CongestionControl)
		}
	}
	udpMTU := options.UDPMTU
	if udpMTU == 0 {
		udpMTU = 1200 - 3
	}
	return &Service[U]{
		ctx:               options.Context,
		logger:            options.Logger,
		tlsConfig:         options.TLSConfig,
		quicConfig:        quicConfig,
		userMap:           make(map[[32]byte]U),
		congestionControl: options.CongestionControl,
		authTimeout:       options.AuthTimeout,
		udpTimeout:        options.UDPTimeout,
		udpMTU:            options.UDPMTU,
		handler:           options.Handler,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[[32]byte]U)
	hashList := make([][32]byte, len(passwordList))
	for index, password := range passwordList {
		hashList[index] = blake3.Sum256([]byte(password))
	}
	for index := range userList {
		userMap[hashList[index]] = userList[index]
	}
	s.userMap = userMap
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if !s.quicConfig.Allow0RTT {
		listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		go func() {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				go s.handleConnection(connection)
			}
		}()
	} else {
		listener, err := qtls.ListenEarly(conn, s.tlsConfig, s.quicConfig)
		if err != nil {
			return err
		}
		s.quicListener = listener
		go func() {
			for {
				connection, hErr := listener.Accept(s.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						s.logger.Debug(E.Cause(hErr, "listener closed"))
					} else {
						s.logger.Error(E.Cause(hErr, "listener closed"))
					}
					return
				}
				go s.handleConnection(connection)
			}
		}()
	}
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	setCongestion(s.ctx, connection, s.congestionControl)
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	session.handle()
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authDone   chan struct{}
	authUser   U
	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*udpPacketConn
}

func (s *serverSession[U]) handle() {
	if s.ctx.Done() != nil {
		go func() {
			select {
			case <-s.ctx.Done():
				s.closeWithError(s.ctx.Err(), 0)
			case <-s.connDone:
			}
		}()
	}
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.handleAuthTimeout()
}

func (s *serverSession[U]) loopUniStreams() {
	for {
		uniStream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err, errCode := s.handleUniStream(uniStream)
			if err != nil {
				s.closeWithError(E.Cause(err, "handle uni stream"), errCode)
			}
		}()
	}
}

func (s *serverSession[U]) handleUniStream(stream *quic.ReceiveStream) (error, uint64) {
	defer stream.CancelRead(0)
	buffer := buf.New()
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request"), ErrorCodeProtocolError
	}
	version := buffer.Byte(0)
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0)), ErrorCodeProtocolError
	}
	command := buffer.Byte(1)
	switch command {
	case CommandAuthenticate:
		select {
		case <-s.authDone:
			return E.New("authentication: multiple authentication requests"), ErrorCodeAuthenticationFailed
		default:
		}
		if buffer.Len() < AuthenticateLen {
			_, err = buffer.ReadFullFrom(stream, AuthenticateLen-buffer.Len())
			if err != nil {
				return E.Cause(err, "authentication: read request"), ErrorCodeAuthenticationTimeout
			}
		}
		var userHash [32]byte
		copy(userHash[:], buffer.Range(2, 2+32))
		user, loaded := s.userMap[userHash]
		if !loaded {
			return E.New("authentication: unknown user blake3 hash ", hex.EncodeToString(userHash[:])), ErrorCodeAuthenticationFailed
		}
		s.authUser = user
		close(s.authDone)
		return nil, 0
	case CommandPacket:
		select {
		case <-s.connDone:
			return s.connErr, 0
		case <-s.authDone:
		}
		message := allocMessage()
		err = readUDPMessage(message, io.MultiReader(bytes.NewReader(buffer.From(2)), stream))
		if err != nil {
			message.release()
			return err, 0
		}
		s.handleUDPMessage(message, true)
		return nil, 0
	case CommandDissociate:
		select {
		case <-s.connDone:
			return s.connErr, 0
		case <-s.authDone:
		}
		if buffer.Len() > 6 {
			return E.New("invalid dissociate message"), 0
		}
		var sessionID uint32
		err = binary.Read(io.MultiReader(bytes.NewReader(buffer.From(2)), stream), binary.BigEndian, &sessionID)
		if err != nil {
			return err, 0
		}
		s.udpAccess.RLock()
		udpConn, loaded := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if loaded {
			udpConn.closeWithError(E.New("remote closed"))
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil, 0
	case CommandHeartbeat:
		select {
		case <-s.connDone:
			return s.connErr, 0
		case <-s.authDone:
		}
		return nil, 0
	default:
		return E.New("unknown command ", command), ErrorCodeBadCommand
	}
}

func (s *serverSession[U]) handleAuthTimeout() {
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-time.After(s.authTimeout):
		s.closeWithError(E.New("authentication timeout"), ErrorCodeAuthenticationTimeout)
	}
}

func (s *serverSession[U]) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			err, errCode := s.handleStream(stream)
			if err != nil {
				stream.CancelRead(0)
				stream.Close()
				s.logger.Error(E.Cause(err, "handle stream request"))
			}
			if errCode != 0 {
				s.closeWithError(E.Cause(err, "handle stream request"), errCode)
			}
		}()
	}
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) (error, uint64) {
	buffer := buf.NewSize(2 + M.MaxSocksaddrLength)
	defer buffer.Release()
	_, err := buffer.ReadAtLeastFrom(stream, 2)
	if err != nil {
		return E.Cause(err, "read request"), ErrorCodeProtocolError
	}
	version, _ := buffer.ReadByte()
	if version != Version {
		return E.New("unknown version ", buffer.Byte(0)), ErrorCodeProtocolError
	}
	command, _ := buffer.ReadByte()
	if command != CommandConnect {
		return E.New("unsupported stream command ", command), ErrorCodeBadCommand
	}
	destination, err := AddressSerializer.ReadAddrPort(io.MultiReader(buffer, stream))
	if err != nil {
		return E.Cause(err, "read request destination"), 0
	}
	select {
	case <-s.connDone:
		return s.connErr, 0
	case <-s.authDone:
	}
	var conn net.Conn = &serverConn{
		Stream:      stream,
		destination: destination,
	}
	if !buffer.IsEmpty() {
		conn = bufio.NewCachedConn(conn, buffer.ToOwned())
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), conn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil, 0
}

func (s *serverSession[U]) closeWithError(err error, errCode uint64) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	_ = s.quicConn.CloseWithError(quic.ApplicationErrorCode(errCode), "")
}

type serverConn struct {
	*quic.Stream
	destination     M.Socksaddr
	responseWritten bool
}

func (c *serverConn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	return n, wrapQUICError(err)
}

func (c *serverConn) Write(p []byte) (int, error) {
	if !c.responseWritten {
		response := buf.NewSize(3 + len(p))
		defer response.Release()
		response.WriteByte(Version)
		response.WriteByte(CommandResponse)
		response.WriteByte(OptionResponseSuccess)
		response.Write(p)
		_, err := c.Stream.Write(response.Bytes())
		if err != nil {
			return 0, wrapQUICError(err)
		}
		c.responseWritten = true
		return len(p), nil
	}
	n, err := c.Stream.Write(p)
	return n, wrapQUICError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.destination
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
