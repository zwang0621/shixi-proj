package collector

import (
	"context"

	"shixi-proj/internal/store"
)

type Collector interface {
	// since: YYYY-MM-DD，可为空
	Collect(ctx context.Context, st *store.Store, since string) error
}
