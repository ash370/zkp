package offlinetx

import "testing"

func TestNoRegulation(t *testing.T) {
	T_offlineTxWithNoRegulation() //33412
}
func TestNoLimitRegulation(t *testing.T) {
	T_offlineTxWithNoLimitRegulation() //39495
}

func TestWithHoldingLimitRegulation(t *testing.T) {
	T_offlineTxWithHoldinglimitRegulation() //48868
}

func TestWithFreqLimitRegulation(t *testing.T) {
	T_offlineTxWithFreqlimitRegulation() //61434
}
