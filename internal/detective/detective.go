package detective

import (
	"context"

	"holmes/internal/model"
)

type Detective interface {
	Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error)
}
