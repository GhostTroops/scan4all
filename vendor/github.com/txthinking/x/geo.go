package x

import "math"

// return m
func Distance(lng1, lat1, lng2, lat2 float64) float64 {
	radius := 6371000.0
	rad := math.Pi / 180.0
	lng1 = lng1 * rad
	lat1 = lat1 * rad
	lng2 = lng2 * rad
	lat2 = lat2 * rad
	theta := lng2 - lng1
	dist := math.Acos(math.Sin(lat1)*math.Sin(lat2) + math.Cos(lat1)*math.Cos(lat2)*math.Cos(theta))
	return dist * radius
}
