package persistence

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// --------------------------------------------------------------------------
// Entity definitions
// --------------------------------------------------------------------------

// UserSite defines sites and permissions for users
type UserSite struct {
	Name     string    `db:"name"`
	User     string    `db:"user"`
	URL      string    `db:"url"`
	PermList string    `db:"permission_list"`
	Created  time.Time `db:"created"`
}

type logintype uint

const (
	// DIRECT login to the site
	DIRECT logintype = iota
	// FLOW or indirect login via login-flow
	FLOW
)

// Login stores user logins
type Login struct {
	ID      int       `db:"id"`
	User    string    `db:"user"`
	Created time.Time `db:"created"`
	Type    logintype `db:"type"`
}

// --------------------------------------------------------------------------
// Repository interface
// --------------------------------------------------------------------------

// Repository defines the methods interacting with the store
type Repository interface {
	CreateAtomic() (Atomic, error)
	GetSitesByUser(user string) ([]UserSite, error)
	StoreSiteForUser(user string, sites []UserSite, a Atomic) (err error)
	StoreLogin(login Login, a Atomic) (err error)
}

// NewRepository creates a new instance using an existing connection
func NewRepository(c Connection) (Repository, error) {
	if !c.Active {
		return nil, fmt.Errorf("no repository connection available")
	}
	return &dbRepository{c}, nil
}

// --------------------------------------------------------------------------
// Repository implementation
// --------------------------------------------------------------------------

type dbRepository struct {
	c Connection
}

func (repo *dbRepository) CreateAtomic() (Atomic, error) {
	return repo.c.CreateAtomic()
}

func (repo *dbRepository) GetSitesByUser(user string) ([]UserSite, error) {
	var (
		err   error
		sites []UserSite
	)

	query := "SELECT name,user,url,permission_list,created FROM USERSITE WHERE lower(user) = ?"

	if err = repo.c.Select(&sites, query, strings.ToLower(user)); err != nil {
		err = fmt.Errorf("could not get the user-sites: %v", err)
		return nil, err
	}

	return sites, nil
}

func (repo *dbRepository) StoreSiteForUser(user string, sites []UserSite, a Atomic) (err error) {
	var (
		atomic *Atomic
		r      sql.Result
		c      int64
	)

	defer func() {
		err = HandleTX(!a.Active, atomic, err)
	}()

	if atomic, err = CheckTX(repo.c, &a); err != nil {
		return
	}

	// brutal approach, delete all sites of the given user, and insert the new ones!
	_, err = atomic.Exec("DELETE FROM USERSITE WHERE user = ?", user)
	if err != nil {
		err = fmt.Errorf("could not delete user-site: %v", err)
		return
	}

	for _, site := range sites {
		r, err = atomic.Exec("INSERT INTO USERSITE (name,user,url,permission_list, created) VALUES (?,?,?,?,?)", site.Name, site.User, site.URL, site.PermList, site.Created)
		if err != nil {
			err = fmt.Errorf("could not insert user-site: %v", err)
			return
		}
		c, err = r.RowsAffected()
		if err != nil {
			err = fmt.Errorf("could not get affected rows: %v", err)
			return
		}
		if c != 1 {
			err = fmt.Errorf("invalid number of rows affected, got %d", c)
			return
		}
	}

	return nil
}

func (repo *dbRepository) StoreLogin(login Login, a Atomic) (err error) {
	var (
		atomic *Atomic
		r      sql.Result
	)

	defer func() {
		err = HandleTX(!a.Active, atomic, err)
	}()

	if atomic, err = CheckTX(repo.c, &a); err != nil {
		return
	}

	r, err = atomic.Exec("INSERT INTO LOGINS (user,created,type) VALUES (?,?,?)", login.User, login.Created, login.Type)
	if err != nil {
		err = fmt.Errorf("could not save login: %v", err)
		return
	}

	c, err := r.RowsAffected()
	if err != nil {
		err = fmt.Errorf("could not get affected rows: %v", err)
		return
	}
	if c != 1 {
		err = fmt.Errorf("invalid number of rows affected, got %d", c)
		return
	}

	return nil
}
