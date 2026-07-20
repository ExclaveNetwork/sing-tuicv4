package tuicv4

import (
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *serverSession[U]) loopMessages() {
	select {
	case <-s.connDone:
		return
	case <-s.authDone:
	}
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"), ErrorCodeProtocolError)
			return
		}
		hErr, errCode := s.handleMessage(message)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"), errCode)
			return
		}
	}
}

func (s *serverSession[U]) handleMessage(data []byte) (error, uint64) {
	if len(data) < 2 {
		return E.New("invalid message"), ErrorCodeProtocolError
	}
	if data[0] != Version {
		return E.New("unknown version ", data[0]), ErrorCodeProtocolError
	}
	switch data[1] {
	case CommandPacket:
		message := allocMessage()
		err := decodeUDPMessage(message, data[2:])
		if err != nil {
			message.releaseMessage()
			return E.Cause(err, "decode UDP message"), 0
		}
		s.handleUDPMessage(message, false)
		return nil, 0
	default:
		return E.New("unknown command ", data[0]), ErrorCodeBadCommand
	}
}

func (s *serverSession[U]) handleUDPMessage(message *udpMessage, udpStream bool) {
	sessionID := message.sessionID
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = newUDPPacketConn(auth.ContextWithUser(s.ctx, s.authUser), s.quicConn, udpStream, s.udpMTU, true, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		})
		udpConn.sessionID = sessionID
		s.udpAccess.Lock()
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnectionEx(newCtx, newConn, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), message.destination, nil)
	}
	udpConn.inputPacket(message)
}
