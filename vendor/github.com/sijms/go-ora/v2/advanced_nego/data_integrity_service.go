package advanced_nego

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network/security"
	"math/big"
)

type dataIntegrityService struct {
	defaultService
	algoID    int
	publicKey []byte
	sharedKey []byte
	iV        []byte
}

func NewDataIntegrityService(comm *AdvancedNegoComm) (*dataIntegrityService, error) {
	output := &dataIntegrityService{
		defaultService: defaultService{
			comm:                  comm,
			serviceType:           3,
			version:               0xB200200,
			availableServiceNames: []string{"", "MD5", "SHA1", "SHA512", "SHA256", "SHA384"},
			availableServiceIDs:   []int{0, 1, 3, 4, 5, 6},
		},
	}
	err := output.buildServiceList([]string{}, true, true)
	//output.selectedServ, err = output.validate(strings.Split(str,","), true)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (serv *dataIntegrityService) readServiceData(subPacketNum int) error {
	var err error
	comm := serv.comm
	serv.version, err = comm.readVersion()
	if err != nil {
		return err
	}
	resp, err := comm.readUB1()
	if err != nil {
		return err
	}
	serv.algoID = int(resp)
	if subPacketNum != 8 {
		return nil
	}
	dhGenLen, err := comm.readUB2()
	if err != nil {
		return err
	}
	dhPrimLen, err := comm.readUB2()
	if err != nil {
		return err
	}
	genBytes, err := comm.readBytes()
	if err != nil {
		return err
	}
	primeBytes, err := comm.readBytes()
	if err != nil {
		return err
	}
	serverPublicKeyBytes, err := comm.readBytes()
	if err != nil {
		return err
	}
	serv.iV, err = comm.readBytes()
	if err != nil {
		return err
	}
	if dhGenLen <= 0 || dhPrimLen <= 0 {
		return errors.New("advanced negotiation error: bad parameter from server")
	}
	byteLen := (dhGenLen + 7) / 8 // this means  if dhGroupPLen % 8 > 0 then byteLen += 1
	if len(serverPublicKeyBytes) != byteLen || len(primeBytes) != byteLen {
		return errors.New("advanced negotiation error: DiffieHellman negotiation out of sync")
	}
	privateKeyBytes := make([]byte, byteLen)
	_, err = rand.Read(privateKeyBytes)
	if err != nil {
		return errors.New("advanced negotiation error: DiffieHellman random private key")
	}
	gen := new(big.Int).SetBytes(genBytes)
	prime := new(big.Int).SetBytes(primeBytes)
	privateKey := new(big.Int).SetBytes(privateKeyBytes)
	serverPublicKey := new(big.Int).SetBytes(serverPublicKeyBytes)
	publicKey := new(big.Int).Exp(gen, privateKey, prime)
	sharedKey := new(big.Int).Exp(serverPublicKey, privateKey, prime)
	serv.publicKey = make([]byte, byteLen)
	publicKey.FillBytes(serv.publicKey)
	serv.sharedKey = make([]byte, byteLen)
	sharedKey.FillBytes(serv.sharedKey)
	tracer := comm.session.Context.ConnOption.Tracer
	tracer.Print("Diffie Hellman Keys:")
	tracer.LogPacket("Generator:", genBytes)
	tracer.LogPacket("Prime:", primeBytes)
	tracer.LogPacket("Private Key:", privateKeyBytes)
	tracer.LogPacket("Public Key:", serv.publicKey)
	tracer.LogPacket("Server Public Key:", serverPublicKeyBytes)
	tracer.LogPacket("Shared Key:", serv.sharedKey)
	return nil
}
func (serv *dataIntegrityService) writeServiceData() error {
	serv.writeHeader(2)
	comm := serv.comm
	comm.writeVersion(serv.getVersion())
	selectedIndices := make([]byte, len(serv.selectedIndices))
	for i := 0; i < len(serv.selectedIndices); i++ {
		index := serv.selectedIndices[i]
		selectedIndices[i] = uint8(serv.availableServiceIDs[index])
		//comm.session.PutBytes(uint8(serv.availableServiceIDs[index]))
	}
	comm.writeBytes(selectedIndices)
	return nil
}

func (serv *dataIntegrityService) getServiceDataLength() int {
	return 12 + len(serv.selectedIndices)
}

func (serv *dataIntegrityService) activateAlgorithm() error {
	serv.comm.session.Context.AdvancedService.SessionKey = serv.sharedKey
	serv.comm.session.Context.AdvancedService.IV = serv.iV
	//return errors.New(fmt.Sprintf("advanced negotiation error: data integrity service algorithm: %d still not supported", serv.algoID))
	var algo security.OracleNetworkDataIntegrity = nil
	var err error
	switch serv.algoID {
	case 0:
		algo = nil
	case 1:
		algo, err = security.NewOracleNetworkHash(md5.New(), serv.sharedKey, serv.iV)
	case 3:
		algo, err = security.NewOracleNetworkHash(crypto.SHA1.New(), serv.sharedKey, serv.iV)
	case 4:
		algo, err = security.NewOracleNetworkHash2(crypto.SHA512.New(), serv.sharedKey, serv.iV)
	case 5:
		algo, err = security.NewOracleNetworkHash2(crypto.SHA256.New(), serv.sharedKey, serv.iV)
	case 6:
		algo, err = security.NewOracleNetworkHash2(crypto.SHA384.New(), serv.sharedKey, serv.iV)
	default:
		err = errors.New(fmt.Sprintf("advanced negotiation error: data integrity service algorithm: %d still not supported", serv.algoID))
	}
	if err != nil {
		return err
	}
	serv.comm.session.Context.AdvancedService.HashAlgo = algo
	return nil
	// you can use also IDs
}
