package model

type Status string

const (
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

type Investigation struct {
	Detective string `json:"detective"`
	Status    Status `json:"status"`
	Error     string `json:"error"`
	Result    any    `json:"result,omitempty"`
}
