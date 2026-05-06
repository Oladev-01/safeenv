package models
import(
	"github.com/google/uuid"
	"time"
)

type Users struct {
	ID *uuid.UUID `json:"id,omitempty"`
	PublicKey string `json:"public_key"`
	EncPrivateKey string `json:"encrypted_private_key"`
	Salt string `json:"salt"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type Teams struct {
	ID *uuid.UUID `json:"id,omitempty"`
	Name string `json:"name"`
	CreatedBy uuid.UUID `json:"created_by"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

type AuthLog struct {
	ID *uuid.UUID `json:"id,omitempty"`
	UserID uuid.UUID `json:"user_id"`
	Reason string `json:"reason"`
}