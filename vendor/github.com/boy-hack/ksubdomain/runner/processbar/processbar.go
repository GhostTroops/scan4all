package processbar

type ProcessData struct {
	SuccessIndex uint64
	SendIndex    uint64
	QueueLength  int64
	RecvIndex    uint64
	FaildIndex   uint64
	Elapsed      int
}
type ProcessBar interface {
	WriteData(data *ProcessData)
	Close()
}
