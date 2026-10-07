package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(connString string) (*pgxpool.Pool, error) {
	var pool *pgxpool.Pool
	var err error

	for i := 0; i < 10; i++ {
		pool, err = pgxpool.New(context.Background(), connString)
		if err == nil {
			if err = pool.Ping(context.Background()); err == nil {
				log.Println("Успешное подключение к PostgreSQL")
				return pool, nil
			}
		}
		log.Printf("⏳ Ожидание PostgreSQL... попытка %d/10", i+1)
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
}

func RunMigrations(pool *pgxpool.Pool) error {
	sqlBytes, err := os.ReadFile("migrations/init.sql")
	if err != nil {
		return fmt.Errorf("ошибка чтения файла миграции: %w", err)
	}

	_, err = pool.Exec(context.Background(), string(sqlBytes))
	if err != nil {
		return fmt.Errorf("ошибка выполнения миграции: %w", err)
	}
	
	log.Println("Миграции успешно применены")
	return nil
}