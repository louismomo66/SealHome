package data

import (
	"errors"

	"gorm.io/gorm"
)

// PeripheralState represents the state of a device peripheral (relay, door sensor, motion sensor, door bell)
type PeripheralState struct {
	gorm.Model
	DeviceID        uint   `gorm:"not null;index:idx_device_type_index,unique" json:"device_id"`
	PeripheralType  string `gorm:"type:varchar(50);not null;index:idx_device_type_index,unique" json:"peripheral_type"`
	PeripheralIndex int    `gorm:"not null;default:0;index:idx_device_type_index,unique" json:"peripheral_index"`
	State           string `gorm:"type:varchar(50);not null" json:"state"`
}

// PeripheralStateRepository implements PeripheralStateInterface
type PeripheralStateRepository struct {
	db *gorm.DB
}

func NewPeripheralStateRepository(db *gorm.DB) PeripheralStateInterface {
	return &PeripheralStateRepository{db: db}
}

// SetState upserts a peripheral state for a device and index
func (r *PeripheralStateRepository) SetState(deviceID uint, peripheralType string, peripheralIndex int, state string) error {
	rec := PeripheralState{}
	result := r.db.Where("device_id = ? AND peripheral_type = ? AND peripheral_index = ?", deviceID, peripheralType, peripheralIndex).First(&rec)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		rec.DeviceID = deviceID
		rec.PeripheralType = peripheralType
		rec.PeripheralIndex = peripheralIndex
		rec.State = state
		return r.db.Create(&rec).Error
	}
	if result.Error != nil {
		return result.Error
	}
	rec.State = state
	return r.db.Save(&rec).Error
}

// GetState returns a single peripheral state
func (r *PeripheralStateRepository) GetState(deviceID uint, peripheralType string, peripheralIndex int) (*PeripheralState, error) {
	var rec PeripheralState
	result := r.db.Where("device_id = ? AND peripheral_type = ? AND peripheral_index = ?", deviceID, peripheralType, peripheralIndex).First(&rec)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &rec, result.Error
}

// GetStatesByDevice returns all peripheral states for a device
func (r *PeripheralStateRepository) GetStatesByDevice(deviceID uint) ([]*PeripheralState, error) {
	var list []*PeripheralState
	result := r.db.Where("device_id = ?", deviceID).Find(&list)
	return list, result.Error
}
