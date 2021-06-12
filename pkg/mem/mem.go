package mem

func Set(arr []byte, val byte) {
	for i := 0; i < len(arr); i++ {
		arr[i] = val
	}
}