package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/samber/lo"
)

const (
	endpoint string = "/realms/test/protocol/openid-connect/userinfo"
)

var (
	url string
)

type (
	Book struct {
		ID     uuid.UUID `json:"id"`
		Author string    `json:"author"`
		Title  string    `json:"title"`
	}
	Error struct {
		Error string `json:"error"`
	}
)

func validateToken(token string) error {
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	request.Header.Add("Authorization", token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return errors.New("Can't reach auth service")
	}

	body := make(map[string]string)
	json.NewDecoder(response.Body).Decode(&body) // nolint errcheck

	if msg, ok := body["error_description"]; ok {
		return errors.New(msg)
	}

	if msg, ok := body["error"]; ok {
		return errors.New(msg)
	}

	return nil
}

func getRolesFromToken(tokenString string) []string {
	token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return nil, nil
	}) //nolint staticcheck

	output := make([]string, 0)

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		output = lo.Map(claims["realm_access"].(map[string]any)["roles"].([]any), func(x any, _ int) string {
			return x.(string)
		})
	}

	return output
}

func validateRealms(realms []string, all bool) func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		if !all {
			for _, realm := range realms {
				if _, found := lo.Find(ctx.Locals("roles").([]string), func(role string) bool {
					return role == realm
				}); found {
					return ctx.Next()
				}
			}

			return ctx.Status(fiber.StatusForbidden).JSON(Error{fmt.Sprintf("Valid realms %s", strings.Join(realms, ", "))})
		}

		all := make([]bool, len(realms))
		for i, realm := range realms {
			if _, found := lo.Find(ctx.Locals("roles").([]string), func(role string) bool {
				return role == realm
			}); found {
				all[i] = true
			}
		}

		if !lo.EveryBy(all, func(x bool) bool { return x }) {
			realmsMissing := lo.Filter(realms, func(_ string, i int) bool {
				return !all[i]
			})

			return ctx.Status(fiber.StatusForbidden).JSON(Error{fmt.Sprintf("No all realms found: %s", strings.Join(realmsMissing, ", "))})
		}

		return ctx.Next()
	}
}

func main() {
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = ":4000"
	}

	keycloak_url, ok := os.LookupEnv("KEYCLOAK_HOST")
	if !ok {
		keycloak_url = "localhost"
	}

	keycloak_port, ok := os.LookupEnv("KEYCLOAK_PORT")
	if !ok {
		keycloak_port = "8080"
	}

	url = fmt.Sprintf("http://%s:%s%s", keycloak_url, keycloak_port, endpoint)

	books := []Book{
		{uuid.New(), "José Saramago", "Ensayo sobre la ceguera"},
	}

	app := fiber.New()

	// Validate token
	app.Use(func(ctx *fiber.Ctx) error {
		if err := validateToken(ctx.Get("Authorization")); err != nil {
			return ctx.Status(fiber.StatusForbidden).JSON(Error{err.Error()})
		}
		return ctx.Next()
	})

	// Roles in context
	app.Use(func(ctx *fiber.Ctx) error {
		token := strings.Split(ctx.Get("Authorization"), " ")[1]
		roles := getRolesFromToken(token)

		ctx.Locals("roles", roles)
		return ctx.Next()
	})

	app.Get("/demo/books", func(ctx *fiber.Ctx) error {
		return ctx.JSON(books)
	})

	app.Post("/demo/books", validateRealms([]string{"admin", "user"}, true), func(ctx *fiber.Ctx) error {
		book := new(Book)

		if err := ctx.BodyParser(book); err != nil {
			return err
		}

		book.ID = uuid.New()

		books = append(books, *book)

		return ctx.SendStatus(fiber.StatusCreated)
	})

	app.Delete("/demo/books/:id", validateRealms([]string{"admin", "user"}, true), func(ctx *fiber.Ctx) error {
		id := ctx.Params("id")

		books = lo.Filter(books, func(book Book, _ int) bool {
			return book.ID.String() != id
		})

		return nil
	})

	log.Fatal(app.Listen(port))
}
