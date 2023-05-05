package auth

import (
	"context"
	"reflect"

	"github.com/germla/auth/auth_identity"
	"github.com/germla/auth/claims"
	"github.com/jinzhu/copier"
	"github.com/qor/qor/utils"
)

// UserStorerInterface user storer interface
type UserStorerInterface interface {
	Save(schema *Schema, context *Context) (user interface{}, userID string, err error)
	Get(claims *claims.Claims, context *Context) (user interface{}, err error)
}

// UserStorer default user storer
type UserStorer struct {
}

// Get defined how to get user with user id
func (UserStorer) Get(Claims *claims.Claims, ucontext *Context) (user interface{}, err error) {
	var tx = ucontext.Auth.GetDB(ucontext.Request)

	if ucontext.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			currentUser := reflect.New(utils.ModelType(ucontext.Auth.Config.UserModel)).Interface()
			if err := tx.NewSelect().Model(ucontext.Auth.Config.UserModel).Where("id = ?", Claims.UserID).Scan(context.Background(), currentUser); err == nil {
				return currentUser, nil
			}
			return nil, ErrInvalidAccount
		}
	}

	var (
		authIdentity = reflect.New(utils.ModelType(ucontext.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: Claims.Provider,
			UID:      Claims.Id,
		}
	)

	if err = tx.NewSelect().Model(ucontext.Auth.Config.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(context.Background(), authIdentity); err == nil {
		if ucontext.Auth.Config.UserModel != nil {
			if authBasicInfo, ok := authIdentity.(interface {
				ToClaims() *claims.Claims
			}); ok {
				currentUser := reflect.New(utils.ModelType(ucontext.Auth.Config.UserModel)).Interface()
				if err = tx.NewSelect().Model(ucontext.Auth.Config.UserModel).Where("id = ?", authBasicInfo.ToClaims().UserID).Scan(context.Background(), currentUser); err == nil {
					return currentUser, nil
				}
				return nil, ErrInvalidAccount
			}
		}

		return authIdentity, nil
	}

	return nil, ErrInvalidAccount
}

// Save defined how to save user
func (UserStorer) Save(schema *Schema, ucontext *Context) (user interface{}, userID string, err error) {
	var tx = ucontext.Auth.GetDB(ucontext.Request)

	if ucontext.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(ucontext.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		err := tx.NewInsert().Model(ucontext.Auth.Config.UserModel).Scan(context.Background(), currentUser)

		return currentUser, schema.UID, err
	}
	return nil, "", nil
}
