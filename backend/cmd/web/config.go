package main

import (
	"log"
	"sealhome/data"
	"sync"

	"gorm.io/gorm"
)

type Config struct{
	DB *gorm.DB
	InfoLog *log.Logger
	ErrorLog *log.Logger
	Wait *sync.WaitGroup
	Models data.Models
	// Mailer Mail
	ErrorChan chan error
	ErrorChanDone chan bool
}