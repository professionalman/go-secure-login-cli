package repository

import "errors"

var (
	ErrNotFound = errors.New("repository record not found")
	ErrConflict = errors.New("repository conflict")
)
