package vmaas

import (
	"strings"

	"github.com/pkg/errors"
)

type ReleaseNode struct {
	VariantSuffix VariantSuffix
	Type          string
	CPEs          []CpeLabel
	Children      []*ReleaseNode
	Parent        *ReleaseNode
}

type ReleaseGraph struct {
	GetByVariant map[VariantSuffix]*ReleaseNode
	GetByCpe     map[CpeLabel][]*ReleaseNode
}

type ReleaseGraphRaw struct {
	Nodes map[string]struct {
		Type string     `json:"type"`
		CPEs []CpeLabel `json:"cpes"`
	} `json:"nodes"`
	Edges map[string][]string `json:"edges"`
}

// Get suffix from release name mappable to product variant suffix
func getVariantSuffix(variant string) (VariantSuffix, error) {
	// we are interested only in rhel release name suffix
	// that we can directly map to rhel product variant
	// and replace "+" with "." because product variants don't contain "+"
	// example:
	// 	release name:     RHEL-9.2.0.Z.MAIN+EUS
	//  product variant:  Appstream-9.2.0.Z.MAIN.EUS
	splitted := strings.SplitN(variant, "-", 2)
	if len(splitted) != 2 {
		return "", errors.New("release name without '-'")
	}
	return VariantSuffix(strings.ReplaceAll(splitted[1], "+", ".")), nil
}

// Build the ReleaseGraph tree structure
func (raw *ReleaseGraphRaw) BuildGraph(cpeID2Label map[CpeID]CpeLabel) *ReleaseGraph {
	g := &ReleaseGraph{
		GetByVariant: make(map[VariantSuffix]*ReleaseNode),
		GetByCpe:     make(map[CpeLabel][]*ReleaseNode),
	}

	// Create all nodes
	for id, data := range raw.Nodes {
		variantSuffix, err := getVariantSuffix(id)
		if err != nil {
			continue
		}

		// extend CPEs by all matching CPEs
		cpes := getMatchingCpes(cpeID2Label, data.CPEs)

		node := &ReleaseNode{
			VariantSuffix: variantSuffix,
			Type:          data.Type,
			CPEs:          cpes,
		}
		g.GetByVariant[variantSuffix] = node

		// Important! Make GetByCpe map only from original CPEs from graphs
		// if we use all matching `cpeLabels`, we will link e.g.
		// cpe:/o:redhat:enterprise_linux:8 with all variants which we don't want
		for _, cpe := range data.CPEs {
			nodes := g.GetByCpe[cpe]
			nodes = append(nodes, node)
			g.GetByCpe[cpe] = nodes
		}
	}

	// Link parent/children based on edges
	for fromID, toIDs := range raw.Edges {
		fromVariant, err := getVariantSuffix(fromID)
		if err != nil {
			continue
		}
		parent := g.GetByVariant[fromVariant]
		for _, toID := range toIDs {
			toVariant, err := getVariantSuffix(toID)
			if err != nil {
				continue
			}
			child := g.GetByVariant[toVariant]
			parent.Children = append(parent.Children, child)
			child.Parent = parent
		}
	}

	return g
}

// Get all parent nodes (ancestors) of a node by a node id - product variant suffix
func (g *ReleaseGraph) GetAncestors(variant VariantSuffix) []*ReleaseNode {
	var ancestors []*ReleaseNode
	node := g.GetByVariant[variant]
	for node != nil && node.Parent != nil {
		ancestors = append(ancestors, node.Parent)
		node = node.Parent
	}
	return ancestors
}

// Get all parent nodes (ancestors) of a node
func (n *ReleaseNode) GetAncestors() []*ReleaseNode {
	var ancestors []*ReleaseNode
	node := *n // don't change caller
	for node.Parent != nil {
		ancestors = append(ancestors, node.Parent)
		node = *node.Parent
	}
	return ancestors
}
