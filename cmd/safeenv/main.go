package main
import (
	"github.com/joho/godotenv"
	"log"
	"github.com/Oladev-01/safeenv/cmd"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("failed to load .env")
	}

	cmd.Execute()
}