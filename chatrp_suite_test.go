package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var pathToProxyCLI string

var _ = BeforeSuite(func() {
	var err error
	pathToProxyCLI, err = gexec.Build("github.com/acrmp/chatrp")
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	gexec.CleanupBuildArtifacts()
})

func TestChatReverseProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chat Reverse Proxy Suite")
}
