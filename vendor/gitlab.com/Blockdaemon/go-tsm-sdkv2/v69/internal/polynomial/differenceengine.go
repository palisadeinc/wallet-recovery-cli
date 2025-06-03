package polynomial

import "gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"

type DifferenceEngine struct {
	firstRow []ec.Scalar
	lastRow  []ec.Scalar
}

type DifferenceEngineInExponent struct {
	firstRow []ec.Point
	lastRow  []ec.Point
}

func NewDifferenceEngine(vals []ec.Scalar) *DifferenceEngine {
	n := len(vals)
	previousColumn := vals

	currentColumn := make([]ec.Scalar, n)
	firstRow := make([]ec.Scalar, n)
	lastRow := make([]ec.Scalar, n)

	firstRow[0] = previousColumn[0]
	lastRow[0] = previousColumn[n-1]
	for col := 1; col < n; col++ {
		for row := 0; row < n-col; row++ {
			currentColumn[row] = previousColumn[row+1].Subtract(previousColumn[row])
		}
		previousColumn = currentColumn
		firstRow[col] = previousColumn[0]
		lastRow[col] = previousColumn[n-col-1]
	}

	return &DifferenceEngine{
		firstRow: firstRow,
		lastRow:  lastRow,
	}
}

func (d *DifferenceEngine) Prev(count int) ec.Scalar {
	for j := 0; j < count; j++ {
		for i := len(d.firstRow) - 2; i >= 0; i-- {
			d.firstRow[i] = d.firstRow[i].Subtract(d.firstRow[i+1])
		}
	}
	return d.firstRow[0]
}

func (d *DifferenceEngine) Next(count int) ec.Scalar {
	for j := 0; j < count; j++ {
		for i := len(d.lastRow) - 2; i >= 0; i-- {
			d.lastRow[i] = d.lastRow[i].Add(d.lastRow[i+1])
		}
	}
	return d.lastRow[0]
}

func NewDifferenceEngineInExponent(vals []ec.Point) *DifferenceEngineInExponent {
	n := len(vals)
	previousColumn := vals

	currentColumn := make([]ec.Point, n)
	firstRow := make([]ec.Point, n)
	lastRow := make([]ec.Point, n)

	firstRow[0] = previousColumn[0]
	lastRow[0] = previousColumn[n-1]
	for col := 1; col < n; col++ {
		for row := 0; row < n-col; row++ {
			currentColumn[row] = previousColumn[row+1].Subtract(previousColumn[row])
		}
		previousColumn = currentColumn
		firstRow[col] = previousColumn[0]
		lastRow[col] = previousColumn[n-col-1]
	}

	return &DifferenceEngineInExponent{
		firstRow: firstRow,
		lastRow:  lastRow,
	}
}

func (d *DifferenceEngineInExponent) Prev(count int) ec.Point {
	for j := 0; j < count; j++ {
		for i := len(d.firstRow) - 2; i >= 0; i-- {
			d.firstRow[i] = d.firstRow[i].Subtract(d.firstRow[i+1])
		}
	}
	return d.firstRow[0]
}

func (d *DifferenceEngineInExponent) Next(count int) ec.Point {
	for j := 0; j < count; j++ {
		for i := len(d.lastRow) - 2; i >= 0; i-- {
			d.lastRow[i] = d.lastRow[i].Add(d.lastRow[i+1])
		}
	}
	return d.lastRow[0]
}
