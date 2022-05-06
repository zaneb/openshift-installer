package main

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/awalterschulze/gographviz"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/asset/kubeconfig"
	"github.com/openshift/installer/pkg/asset/tls"
)

var (
	graphOpts struct {
		outputFile string
	}
)

func newGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Outputs the internal dependency graph for installer",
		Long:  "",
		Args:  cobra.ExactArgs(0),
		RunE:  runGraphCmd,
	}
	cmd.PersistentFlags().StringVar(&graphOpts.outputFile, "output-file", "", "file where the graph is written, if empty prints the graph to Stdout.")
	return cmd
}

func isCertKey(a asset.Asset) bool {
	kind := reflect.TypeOf(a).Elem()
	if kind.Kind() != reflect.Struct {
		return false
	}
	certField, certExists := kind.FieldByName("CertKey")
	return certExists && certField.Type.AssignableTo(reflect.TypeOf(tls.CertKey{}))
}

func isCABundle(a asset.Asset) bool {
	kind := reflect.TypeOf(a).Elem()
	if kind.Kind() != reflect.Struct {
		return false
	}
	bundleField, bundleExists := kind.FieldByName("CertBundle")
	return bundleExists && bundleField.Type.AssignableTo(reflect.TypeOf(tls.CertBundle{}))
}

func overrideWritable(a asset.Asset) writability {
	switch assetName(a) {
	case "AdminKubeConfigSignerCertKey", "AdminKubeConfigClientCertKey", "KubeAPIServerLocalhostSignerCertKey", "KubeAPIServerServiceNetworkSignerCertKey", "KubeAPIServerLBSignerCertKey":
		if !isCertKey(a) {
			panic(fmt.Errorf("%s is not a CertKey", assetName(a)))
		}
		return override
	default:
		return nonrw
	}
}


type writability int
const (
	nonrw writability = iota
	rw
	override
	overrideEffective
)

func isWritable(a asset.Asset) bool {
	_, ok := a.(asset.WritableAsset)
	return ok
}

func isReadWrite(a asset.Asset) writability {
	if wa, ok := a.(asset.WritableAsset); ok {
		_, err := wa.Load(&failureFetcher{})
		if err != nil {
			return rw
		}
	}
	return overrideWritable(a)
}

func assetName(a asset.Asset) string {
	return reflect.TypeOf(a).Elem().Name()
}

type assetGraph map[string]map[string]writability

func (ag assetGraph) insert(parent, child string, value writability) {
	if _, exists := ag[parent]; !exists {
		ag[parent] = map[string]writability{}
	}
	ag[parent][child] = value
}

func reverseGraph(root asset.Asset) assetGraph {
	rName := assetName(root)
	isRW := isReadWrite(root)
	g := assetGraph{}
	for _, d := range root.Dependencies() {
		dName := assetName(d)
		g.insert(dName, rName, isRW)

		subGraph := reverseGraph(d)
		for k, v := range subGraph {
			for p, b := range v {
				g.insert(k, p, b)
			}
		}
	}
	return g
}

func parents(a string, rg assetGraph) []string {
	result := []string{}
	for p, w := range rg[a] {
		if w != nonrw {
			result = append(result, p)
		} else {
			gps := parents(p, rg)
			fmt.Fprintf(os.Stderr, "Unloadable intermediate %s => %s\n", p, strings.Join(gps, ", "))
			result = append(result, gps...)
		}
	}
	return result
}

func getAllWritableParents(constituents []asset.Asset, root asset.Asset) []asset.Asset {
	rg := reverseGraph(root)
	names := map[string]bool{}
	for _, c := range constituents {
		cName := assetName(c)
		names[cName] = true
		isRW := isReadWrite(c)
		if isRW == nonrw {
			ps := parents(cName, rg)
			fmt.Fprintf(os.Stderr, "Parents of %s: %s\n", cName, strings.Join(ps, ", "))
			for _, p := range ps {
				names[p] = true
			}
		}
	}
	allDeps := getAllDependencies(root)
	output := []asset.Asset{}
	for _, a := range(allDeps) {
		aName := assetName(a)
		if unseen, present := names[aName]; (present && unseen) || isReadWrite(a) == override {
			output = append(output, a)
			names[aName] = false
		}
	}
	return output
}

func getAllDependencies(a asset.Asset) []asset.Asset {
	deps := []asset.Asset{a}
	for _, d := range a.Dependencies() {
		deps = append(deps, getAllDependencies(d)...)
	}

	return deps
}

func dependencyNameList(deps []asset.Asset) string {
	names := []string{}
	for _, d := range deps {
		names = append(names, assetName(d))
	}
	return strings.Join(names, ", ")
}

type rootTarget struct{}
func (rt *rootTarget) Dependencies() []asset.Asset {
	assets := []asset.Asset{}
	for _, a := range clusterTarget.assets {
		assets = append(assets, a)
	}
	return assets
}
func (rt *rootTarget) Generate(asset.Parents) error {
	return nil
}
func (rt *rootTarget) Name() string {
	return "root"
}

var failureFetcherFailure = fmt.Errorf("Tried to load file")
type failureFetcher struct{}
func (ff failureFetcher) FetchByName(string) (*asset.File, error) {
	return nil, failureFetcherFailure
}
func (ff failureFetcher) FetchByPattern(string) ([]*asset.File, error) {
	return nil, failureFetcherFailure
}

func runGraphCmd(cmd *cobra.Command, args []string) error {
	g := gographviz.NewGraph()
	g.SetName("G")
	g.SetDir(true)
	g.SetStrict(true)

	/*
	tNodeAttr := map[string]string{
		string(gographviz.Shape): "box",
		string(gographviz.Style): "filled",
	}
	for _, t := range targets {
		name := fmt.Sprintf("%q", fmt.Sprintf("Target %s", t.name))
		g.AddNode("G", name, tNodeAttr)
		for _, dep := range t.assets {
			addEdge(g, name, dep)
		}
	}
	*/
	g.AddSubGraph("G", "overrides", map[string]string{"label": "overrides"})
	constituents := []asset.Asset{}
	for _, c := range getAllDependencies(&kubeconfig.AdminClient{}) {
		// CABundles don't add any new information
		if !isCABundle(c) {
			constituents = append(constituents, c)
		}
	}
	fmt.Fprintf(os.Stderr, "Got initial constituents: %s\n", dependencyNameList(constituents))
	for _, p := range getAllWritableParents(constituents, &rootTarget{}) {
		addEdge(g, "overrides", p)
	}

	g.AddAttr("G", "rankdir", "LR")
	r := regexp.MustCompile(`[. ]`)
	for _, node := range g.Nodes.Nodes {
		cluster := r.Split(node.Name, -1)[0][1:]
		subgraphName := "cluster_" + cluster
		_, ok := g.SubGraphs.SubGraphs[subgraphName]
		if !ok {
			g.AddSubGraph("G", subgraphName, map[string]string{"label": cluster})
		}
		g.AddNode(subgraphName, node.Name, nil)
	}

	out := os.Stdout
	if graphOpts.outputFile != "" {
		f, err := os.Create(graphOpts.outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	if _, err := io.WriteString(out, g.String()); err != nil {
		return err
	}
	return nil
}

func addEdge(g *gographviz.Graph, parent string, asset asset.Asset) {
	name := fmt.Sprintf("%q", reflect.TypeOf(asset).Elem())

	if !g.IsNode(name) {
		logrus.Debugf("adding node %s", name)
		colour := "red"
		switch isReadWrite(asset) {
		case nonrw:
			if !isWritable(asset) {
				colour = "grey"
			}
		case rw:
			colour = "green"
		case override:
		//case override, overrideEffective:
			colour = "blue"
		}
		g.AddNode("G", name, map[string]string{"color": colour})
	}
	if !isEdge(g, name, parent) {
		logrus.Debugf("adding edge %s -> %s", name, parent)
		g.AddEdge(name, parent, true, nil)
	}

	deps := asset.Dependencies()
	for _, dep := range deps {
		addEdge(g, name, dep)
	}
}

func isEdge(g *gographviz.Graph, src, dst string) bool {
	for _, edge := range g.Edges.Edges {
		if edge.Src == src && edge.Dst == dst {
			return true
		}
	}
	return false
}
