package api
import (
	"log"
	"fmt"
	"net/http"
	"github.com/Oladev-01/safeenv/internal/model"
	"github.com/google/uuid"
)


func (c *SupabaseClient) CreateLog(log interface{}, endpoint string) error {
	resp, err := c.MakeDBRequest("POST", endpoint, log, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create log")
	}

	return nil
}

func (c *SupabaseClient) AuthLogger(userID uuid.UUID, reason error) {
	url := fmt.Sprintf("auth_log")
	newLog := models.AuthLog{
		UserID: userID,
		Reason: reason.Error(),
	}

	
	if err := c.CreateLog(newLog, url); err != nil {
		log.Printf("failed to create log")
	}
}