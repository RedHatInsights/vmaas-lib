package vmaas

import (
	"strings"

	"github.com/pkg/errors"
)

type ReleaseNode struct {
	VariantSuffix VariantSuffix
	Type          string
	CPEs          []string
	Children      []*ReleaseNode
	Parent        *ReleaseNode
}

type ReleaseGraph struct {
	GetByVariant map[VariantSuffix]*ReleaseNode
}

type ReleseGraphRaw struct {
	Nodes map[string]struct {
		Type string   `json:"type"`
		CPEs []string `json:"cpes"`
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
func (raw *ReleseGraphRaw) BuildGraph() *ReleaseGraph {
	g := &ReleaseGraph{GetByVariant: make(map[VariantSuffix]*ReleaseNode)}

	// Create all nodes
	for id, data := range raw.Nodes {
		variantSuffix, err := getVariantSuffix(id)
		if err != nil {
			continue
		}
		g.GetByVariant[variantSuffix] = &ReleaseNode{
			VariantSuffix: variantSuffix,
			Type:          data.Type,
			CPEs:          data.CPEs,
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
