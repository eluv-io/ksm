package ksm

import (
	"crypto/rand"
	mathRand "math/rand"
)

// ContentKey is a interface that fetch asset content key and duration.
type ContentKey interface {
	FetchContentKey(assetID []byte) ([]byte, []byte, error)
	FetchContentKeyDuration(assetID []byte) (*CkcContentKeyDurationBlock, error)
	FetchOfflineKey(assetID []byte) (*CkcOfflineKeyBlock, error)
}

var (
	_ ContentKey = RandomContentKey{}
)

// RandomContentKey is a object that implements ContentKey interface.
type RandomContentKey struct {
}

// FetchContentKey returns content key and iv for the given assetId.
func (RandomContentKey) FetchContentKey(assetID []byte) ([]byte, []byte, error) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	return key, iv, nil
}

// FetchContentKeyDuration returns CkcContentKeyDurationBlock for the given assetId.
func (RandomContentKey) FetchContentKeyDuration(assetID []byte) (*CkcContentKeyDurationBlock, error) {

	LeaseDuration := mathRand.Uint32()  // The duration of the lease, if any, in seconds.
	RentalDuration := mathRand.Uint32() // The duration of the rental, if any, in seconds.

	return NewCkcContentKeyDurationBlock(LeaseDuration, RentalDuration, ContentKeyPersisted), nil
}

func (RandomContentKey) FetchOfflineKey(assetID []byte) (*CkcOfflineKeyBlock, error) {
	contentID := make([]byte, 16)
	rand.Read(contentID)
	// Print to validate against verify_ckc output
	// fmt.Printf("contentID: %x\n", contentID)
	storageDuration := uint32(0) //mathRand.Uint32()
	playbackDuration := uint32(0) //mathRand.Uint32()
	titleID := make([]byte, 16)
	rand.Read(titleID)
	return NewCkcOfflineKeyBlock(contentID, storageDuration, playbackDuration, titleID), nil
}

// CKCPayload is a object that store ckc payload.
type CKCPayload struct {
	SK             []byte //Session key
	HU             []byte
	R1             []byte
	IntegrityBytes []byte
}
