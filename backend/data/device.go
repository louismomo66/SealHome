package data

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// Device represents the devices table in the database.
type Device struct {
	gorm.Model
	DeviceType string `gorm:"type:varchar(100);not null" json:"device_type"`
	DeviceName string `gorm:"type:varchar(100);not null" json:"device_name"`
	Location   string `gorm:"type:varchar(200);not null" json:"location"`
	MACAddress string `gorm:"type:varchar(17);uniqueIndex;not null" json:"mac_address"`

	UserID    uint           `gorm:"not null" json:"user_id"`
	User      User           `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// DeviceRepository implements DeviceInterface using GORM.
type DeviceRepository struct {
	db *gorm.DB
}

// NewDeviceRepository creates a new instance of DeviceRepository.
func NewDeviceRepository(db *gorm.DB) DeviceInterface {
	return &DeviceRepository{db: db}
}

// GetAll retrieves all devices from the database.
func (r *DeviceRepository) GetAll() ([]*Device, error) {
	var devices []*Device
	result := r.db.Find(&devices)
	return devices, result.Error
}

// GetDevicesByUserID retrieves all devices belonging to a specific user.
func (r *DeviceRepository) GetDevicesByUserID(userID uint) ([]*Device, error) {
	var devices []*Device
	result := r.db.Where("user_id = ?", userID).Find(&devices)
	return devices, result.Error
}

// GetOne retrieves a device by its ID.
func (r *DeviceRepository) GetOne(id uint) (*Device, error) {
	var device Device
	result := r.db.First(&device, id)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &device, result.Error
}

// AssignDevice assigns a device to a user.
// It ensures that each device is uniquely assigned and handles the assignment logic.
func (r *DeviceRepository) AssignDevice(userID uint, device *Device) error {
	// Start a transaction to ensure atomicity
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Check if the user exists
		var user User
		if err := tx.First(&user, userID).Error; err != nil {
			return err
		}

		// Check if the device with the same MAC address already exists
		var existingMACDevice Device
		if err := tx.Where("mac_address = ?", device.MACAddress).First(&existingMACDevice).Error; err == nil {
			return errors.New("device with this MAC address already exists")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		// Assign the device to the user
		device.UserID = userID
		if err := tx.Create(device).Error; err != nil {
			return err
		}

		return nil
	})
}
