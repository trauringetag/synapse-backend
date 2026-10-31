package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// PgxUnitOfWork — реализация порта domain.UnitOfWork поверх pgxpool.Pool.
//
// Run открывает транзакцию, кладёт её в контекст (domain.WithTx) и вызывает
// fn. Все *Tx-методы репозиториев слоя persistence достают tx из контекста
// (domain.TxFromContext) и выполняют запросы внутри неё, поэтому набор
// операций «UPDATE users + UPDATE refresh_tokens» или «DELETE users +
// UPDATE refresh_tokens» становится атомарным:
//   - ошибка fn -> ROLLBACK (ни одно изменение не применяется);
//   - успех fn   -> COMMIT.
type PgxUnitOfWork struct {
	pool *pgxpool.Pool
}

// Компиляционная проверка: реализация удовлетворяет порту домена.
var _ domain.UnitOfWork = (*PgxUnitOfWork)(nil)

func NewUnitOfWork(pool *pgxpool.Pool) *PgxUnitOfWork {
	return &PgxUnitOfWork{pool: pool}
}

// runTxOptions — параметры транзакций UnitOfWork. READ COMMITTED достаточно:
// атомарность обеспечивает сам факт общей транзакции, а гонки между
// конкурентными ротациями закрывает блокирующий Rotate (SELECT ... FOR UPDATE).
var runTxOptions = pgx.TxOptions{}

func (u *PgxUnitOfWork) Run(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if u == nil || u.pool == nil {
		return errors.New("unit of work: пул соединений не настроен")
	}
	tx, err := u.pool.BeginTx(ctx, runTxOptions)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p) // пробрасываем панику выше — транзакция откатана
		}
	}()

	if err = fn(domain.WithTx(ctx, tx)); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			return errors.Join(err, rbErr)
		}
		return err
	}
	return tx.Commit(ctx)
}

// interfaceAssertions — гарантируем, что pgx.Tx и *pgxpool.Pool остаются
// взаимозаменяемыми для внутреннего dbQuerier (общее SQL-тело для tx/pool).
var (
	_ dbQuerier = (pgx.Tx)(nil)
	_ dbQuerier = (*pgxpool.Pool)(nil)
)
