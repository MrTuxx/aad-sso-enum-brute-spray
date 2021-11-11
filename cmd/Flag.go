package main

type Flag struct {
	set   bool
	value string
}

func (sf *Flag) Set(x string) error {
	sf.value = x
	sf.set = true
	return nil
}

func (sf *Flag) String() string {
	return sf.value
}
