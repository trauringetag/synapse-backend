package handler

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// mockStore — потокобезопасное in-memory хранилище, реализующее интерфейсы
// UserStore и TokenStore. Позволяет гонять полный сценарий
// (регистрация → login → refresh → replay-атака → logout) без PostgreSQL.
type mockStore struct {
	mu           sync.Mutex
	usersByID    map[uuid.UUID]*domain.User
	usersByEmail map[string]*domain.User
	tokens       map[string]*domain.RefreshToken // hash refresh-токена -> запись
}

func newMockStore() *mockStore {
	return &mockStore{
		usersByID:    map[uuid.UUID]*domain.User{},
		usersByEmail: map[string]*domain.User{},
		tokens:       map[string]*domain.RefreshToken{},
	}
}

// seedUser добавляет пользователя напрямую (например, с готовым bcrypt-хешем).
func (s *mockStore) seedUser(u *domain.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersByID[u.ID] = u
	s.usersByEmail[u.Email] = u
}

// ------------------------- интерфейс UserStore -------------------------

// Create дублирует ограничение UNIQUE(email) через domain.ErrConflict.
func (s *mockStore) Create(ctx context.Context, email, passwordHash, role, firstName, lastName string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByEmail[email]; ok {
		return nil, domain.ErrConflict
	}
	u := &domain.User{
		ID: uuid.New(), Email: email, PasswordHash: passwordHash, Role: role,
		Status: domain.StatusActive, FirstName: firstName, LastName: lastName,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	s.usersByID[u.ID] = u
	s.usersByEmail[u.Email] = u
	return u, nil
}

func (s *mockStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.usersByID[id]; ok {
		return u, nil
	}
	return nil, domain.ErrNotFound
}

func (s *mockStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.usersByEmail[email]; ok {
		return u, nil
	}
	return nil, domain.ErrNotFound
}

// List воспроизводит пагинацию и фильтры role/status/search как в SQL.
func (s *mockStore) List(ctx context.Context, f domain.UserListFilter) (*domain.UserListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 10
	}
	filtered := make([]domain.User, 0, len(s.usersByID))
	for _, u := range s.usersByID {
		if f.Role != "" && u.Role != f.Role {
			continue
		}
		if f.Status != "" && u.Status != f.Status {
			continue
		}
		if f.Search != "" {
			hay := strings.ToLower(u.Email + " " + u.FirstName + " " + u.LastName)
			if !strings.Contains(hay, strings.ToLower(f.Search)) {
				continue
			}
		}
		filtered = append(filtered, *u)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Email < filtered[j].Email })
	total := int64(len(filtered))
	totalPages := (total + int64(f.Limit) - 1) / int64(f.Limit)
	start := (f.Page - 1) * f.Limit
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + f.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return &domain.UserListResult{Items: filtered[start:end], Page: f.Page, Limit: f.Limit, Total: total, TotalPages: totalPages}, nil
}

func (s *mockStore) ReplaceProfile(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if dup, ok2 := s.usersByEmail[email]; ok2 && dup.ID != id {
		return nil, domain.ErrConflict
	}
	delete(s.usersByEmail, u.Email)
	u.Email, u.FirstName, u.LastName = email, firstName, lastName
	u.UpdatedAt = time.Now()
	s.usersByEmail[email] = u
	return u, nil
}

func (s *mockStore) Update(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status *string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if email != nil {
		if dup, ok2 := s.usersByEmail[*email]; ok2 && dup.ID != id {
			return nil, domain.ErrConflict
		}
		delete(s.usersByEmail, u.Email)
		u.Email = *email
		s.usersByEmail[u.Email] = u
	}
	if firstName != nil {
		u.FirstName = *firstName
	}
	if lastName != nil {
		u.LastName = *lastName
	}
	if passwordHash != nil {
		u.PasswordHash = *passwordHash
	}
	if status != nil {
		u.Status = *status
	}
	u.UpdatedAt = time.Now()
	return u, nil
}

func (s *mockStore) Replace(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if dup, ok2 := s.usersByEmail[email]; ok2 && dup.ID != id {
		return nil, domain.ErrConflict
	}
	delete(s.usersByEmail, u.Email)
	u.Email, u.FirstName, u.LastName = email, firstName, lastName
	u.PasswordHash, u.Status = passwordHash, status
	u.UpdatedAt = time.Now()
	s.usersByEmail[email] = u
	return u, nil
}

// Delete повторяет защиту БД: администратора удалить нельзя (ErrProtected).
func (s *mockStore) Delete(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	if !ok {
		return domain.ErrNotFound
	}
	if u.Role == domain.RoleAdmin {
		return domain.ErrProtected
	}
	delete(s.usersByID, id)
	delete(s.usersByEmail, u.Email)
	return nil
}

// ------------------------- интерфейс TokenStore -------------------------

func (s *mockStore) Store(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenHash] = &domain.RefreshToken{
		ID: uuid.New(), UserID: userID, TokenHash: tokenHash,
		ExpiresAt: expiresAt, Revoked: false, CreatedAt: time.Now(),
	}
	return nil
}

func (s *mockStore) GetActive(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenHash]
	if !ok || t.Revoked || t.ExpiresAt.Before(time.Now()) {
		return nil, domain.ErrNotFound
	}
	return t, nil
}

// Rotate воспроизводит транзакционную ротацию: старый токен гасится, создается наследник.
// Повторное использование ОТЗЫВАННОГО токена -> ErrRefreshTokenReplay (детект replay-атаки).
func (s *mockStore) Rotate(ctx context.Context, oldHash string, expectedUserID uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[oldHash]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if t.Revoked {
		return nil, domain.ErrRefreshTokenReplay
	}
	if t.ExpiresAt.Before(time.Now()) {
		return nil, domain.ErrNotFound
	}
	if t.UserID != expectedUserID {
		return nil, domain.ErrNotFound
	}
	u, ok := s.usersByID[t.UserID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if u.Status != domain.StatusActive {
		// как в БД: гасим все токены неактивного пользователя
		for _, tt := range s.tokens {
			if tt.UserID == u.ID {
				tt.Revoked = true
			}
		}
		return nil, domain.ErrInactiveTokenUser
	}
	newHash, expiresAt, err := createSuccessor(u)
	if err != nil {
		return nil, err
	}
	t.Revoked = true
	s.tokens[newHash] = &domain.RefreshToken{
		ID: uuid.New(), UserID: u.ID, TokenHash: newHash,
		ExpiresAt: expiresAt, Revoked: false, CreatedAt: time.Now(),
	}
	return u, nil
}

func (s *mockStore) Revoke(ctx context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[tokenHash]; ok {
		t.Revoked = true
	}
	return nil
}

func (s *mockStore) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.UserID == userID {
			t.Revoked = true
		}
	}
	return nil
}

// Компиляционные проверки: моки реализуют порты репозиториев из домена
// (единственный источник правды — internal/domain/ports.go).
var (
	_ domain.UserRepository         = (*mockStore)(nil)
	_ domain.RefreshTokenRepository = (*mockStore)(nil)
	// Алиасы use-case слоя указывают на те же самые интерфейсы domain.
	_ usecase.UserRepository  = (*mockStore)(nil)
	_ usecase.TokenRepository = (*mockStore)(nil)
)
