package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/dswarbrick/smart/ioctl"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nitrite"
)

type NsmMessage struct {
	request  syscall.Iovec
	response syscall.Iovec
}

const NsmRequestMaxSize = 0x1000
const NsmResponseMaxSize = 0x3000

type Response struct {
	Attestation struct {
		Document []byte
	}

	GetRandom struct {
		Random []byte
	}

	Error string
}

func main() {
	time.Sleep(15 *time.Second)
	fmt.Println("hello")
	// Give a chance to see any output in the console
	defer time.Sleep(1 * time.Minute)

	nsm, err := os.OpenFile("/dev/nsm", os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("error opening device: %v\n", err)
		return
	}
	defer func() {_ = nsm.Close()}()

	attestationDocument, err := makeAttestationRequest(nsm)
	if err != nil {
		fmt.Printf("error making request: %v", err)
		return
	}

	verifyResult, err := nitrite.Verify(attestationDocument, nitrite.VerifyOptions{})
	if err != nil {
		fmt.Printf("error verifying: %v", err)
		return
	}
	jsonified, err := json.MarshalIndent(verifyResult, "> ", " ")
	if err != nil {
		fmt.Printf("error marshalling: %v", err)
		return
	}

	fmt.Println(string(jsonified))

	err = makeGetRandom(nsm)
	if err != nil {
		fmt.Printf("error making request: %v", err)
		return
	}

}

func makeGetRandom(nsm *os.File) error {
	request := map[string]interface{} {
		"GetRandom": struct{}{},
	}

	response := &Response{}

	err := makeRequest(nsm, request, response)
	if err != nil {
		return  err
	}

	fmt.Printf("Random bytes: %s\n", base64.StdEncoding.EncodeToString(response.GetRandom.Random))

	return nil
}

func makeAttestationRequest(nsm *os.File) ([]byte, error){
	request := map[string]interface{} {
		"Attestation": struct{}{},
	}

	response := &Response{}

	err := makeRequest(nsm, request, response)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Error code: %s\n", response.Error)

	fmt.Printf("Attestation doc: %v\n", response.Attestation)

	return response.Attestation.Document, nil
}


func makeRequest(nsm *os.File, request, response interface{}) error {
	requestBytes, err := cbor.Marshal(&request)
	if err != nil {
		return fmt.Errorf("error marshalling request: %v", err)
	}

	responseBytes := make([]byte, NsmResponseMaxSize, NsmResponseMaxSize)

	message := NsmMessage{}
	message.request.Base = &requestBytes[0]
	message.request.Len = uint64(len(requestBytes))
	message.response.Base = &responseBytes[0]
	message.response.Len = NsmResponseMaxSize

	requestCode := ioctl.Iowr(0x0A, 0, unsafe.Sizeof(message))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, nsm.Fd(), requestCode, uintptr(unsafe.Pointer(&message)))
	if errno != 0 {
		return fmt.Errorf("error from syscall: %v", errno)
	}

	fmt.Printf("response bytes: %s\n", base64.StdEncoding.EncodeToString(responseBytes))

	err = cbor.Unmarshal(responseBytes, response)
	if err != nil {
		return fmt.Errorf("error unmarshalling response: %v", err)

	}

	return nil
}


