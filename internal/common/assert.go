package common

func AssertImpl(predicate bool) {
	if !predicate {
		panic(ImplementationErr)
	}
}