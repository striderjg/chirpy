package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/striderjg/chirpy/internal/auth"
	"github.com/striderjg/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	secret         string
	polkaKey       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(rw, req)
	})
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type:", "text/html")
	page := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())
	w.Write([]byte(page))
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		errorResponce(403, "Not Authorized", w)
		return
	}

	cfg.fileserverHits.Store(0)
	if err := cfg.dbQueries.DeleteUsers(r.Context()); err != nil {
		log.Printf("Error deleting users: %s", err)
		errorResponce(500, "Error DeleteUsers", w)
		return
	}
	w.Write([]byte{})
}

// POST /api/users
func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	var params parameters
	if err := decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		errorResponce(500, "Something went wrong", w)
		return
	}

	if len(params.Email) == 0 {
		errorResponce(400, "Must send an email address", w)
		return
	}
	if len(params.Password) == 0 {
		errorResponce(400, "User Must have Password", w)
		return
	}

	hashedPwd, err := auth.HashPassword(params.Password)
	if err != nil {
		errorResponce(500, "Error hashing password", w)
		return
	}

	usr, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPwd,
	})
	if err != nil {
		errorResponce(400, "Unable to create user", w)
		return
	}
	retUser := User{
		ID:          usr.ID,
		CreatedAt:   usr.CreatedAt,
		UpdatedAt:   usr.UpdatedAt,
		Email:       usr.Email,
		IsChirpyRed: usr.IsChirpyRed,
	}
	jsonResponce(201, retUser, w)
}

// PUT /api/users
func (cfg *apiConfig) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponce(401, "Forbidden", w)
		return
	}
	usrID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		errorResponce(401, "Forbidden", w)
		return
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		errorResponce(500, "Something went wrong", w)
		return
	}
	if len(params.Email) == 0 || len(params.Password) == 0 {
		errorResponce(400, "Must send username and pass", w)
		return
	}

	hashedPwd, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %s\n", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	usr, err := cfg.dbQueries.UpdateUserByID(r.Context(), database.UpdateUserByIDParams{
		ID:             usrID,
		Email:          params.Email,
		HashedPassword: hashedPwd,
	})
	if err != nil {
		log.Printf("Error UpdateUserByID: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	jsonResponce(200,
		User{
			ID:          usr.ID,
			Email:       usr.Email,
			CreatedAt:   usr.CreatedAt,
			UpdatedAt:   usr.UpdatedAt,
			IsChirpyRed: usr.IsChirpyRed,
		}, w,
	)
}

// POST /api/login
func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(r.Body)
	var params parameters
	if err := decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		errorResponce(500, "Something went wrong", w)
		return
	}
	if len(params.Email) == 0 {
		errorResponce(400, "Must send an email", w)
		return
	}
	if len(params.Password) == 0 {
		errorResponce(400, "Must send a pasword", w)
		return
	}

	usr, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		errorResponce(401, "Incorrect email or password", w)
		return
	}
	if err := auth.CheckPasswordHash(params.Password, usr.HashedPassword); err != nil {
		errorResponce(401, "Incorrect email or password", w)
		return
	}
	token, err := auth.MakeJWT(usr.ID, cfg.secret, time.Hour)
	if err != nil {
		errorResponce(500, "Something went wrong", w)
		log.Printf("Error creating JWT: %s", err.Error())
		return
	}
	refershToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error MakeRefreshToken: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	_, err = cfg.dbQueries.SetRefreshToken(r.Context(), database.SetRefreshTokenParams{
		Token:  refershToken,
		UserID: usr.ID,
	})
	if err != nil {
		log.Printf("Error SetRefreshToken: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}

	jsonResponce(200,
		User{
			ID:           usr.ID,
			CreatedAt:    usr.CreatedAt,
			UpdatedAt:    usr.UpdatedAt,
			Email:        usr.Email,
			IsChirpyRed:  usr.IsChirpyRed,
			Token:        token,
			RefreshToken: refershToken,
		}, w)
}

// POST /api/refresh
func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error GetBearerToken: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	usr, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		errorResponce(401, "Forbidden", w)
		return
	}
	accessToken, err := auth.MakeJWT(usr.ID, cfg.secret, time.Hour)
	if err != nil {
		log.Printf("Error MakeJWT: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	jsonResponce(200,
		struct {
			Token string `json:"token"`
		}{
			Token: accessToken,
		}, w,
	)
}

// POST /api/revoke
func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponce(400, "Must have token in header", w)
		return
	}
	if err := cfg.dbQueries.RevokeToken(r.Context(), refreshToken); err != nil {
		errorResponce(400, "No token to revoke", w)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) handleGetChirps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		log.Printf("Error Fetching Chirps\n")
		errorResponce(500, "Something went wrong", w)
		return
	}
	retChirps := make([]Chirp, len(chirps))
	for i, chirp := range chirps {
		retChirps[i].ID = chirp.ID
		retChirps[i].CreatedAt = chirp.CreatedAt
		retChirps[i].UpdatedAt = chirp.UpdatedAt
		retChirps[i].Body = chirp.Body
		retChirps[i].UserID = chirp.UserID
	}
	jsonResponce(200, retChirps, w)
}

// GET /api/chirps/{chirpID}
func (cfg *apiConfig) handleGetChirpByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		errorResponce(400, "Bad ID", w)
		return
	}
	chirp, err := cfg.dbQueries.GetChripById(r.Context(), id)
	if err != nil {
		errorResponce(404, "Not Found", w)
		return
	}
	jsonResponce(200,
		Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		},
		w,
	)
}

// DELETE /api/chirps/{chirpID}
func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		errorResponce(401, "Unauthorized", w)
		return
	}
	usrID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		errorResponce(401, "Unauthorized", w)
		return
	}
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error Parsing chirpID from path: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	chirp, err := cfg.dbQueries.GetChripById(r.Context(), chirpID)
	if err != nil {
		errorResponce(404, "Not Found", w)
		return
	}
	if chirp.UserID != usrID {
		errorResponce(403, "Forbidden", w)
		return
	}
	if err := cfg.dbQueries.DeleteChirpById(r.Context(), chirp.ID); err != nil {
		log.Printf("Error DeleteChirpById: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	w.WriteHeader(204)
	return
}

// POST /api/chirps
func (cfg *apiConfig) handlePostChirp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type paramaters struct {
		Body string `json:"body"`
	}
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error GetBearerToken: %s", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	usrId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		errorResponce(401, "Not Authorized", w)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var params paramaters
	if err := decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		errorResponce(500, "Something went wrong", w)
		return
	}

	if len(params.Body) == 0 {
		errorResponce(400, "No Chirp Recieved", w)
		return
	}

	if len(params.Body) > 140 {
		errorResponce(400, "Chirp is too long", w)
		return
	}

	words := strings.Split(params.Body, " ")
	filteredWords := make([]string, 0, len(words))
	for _, word := range words {
		lowerCaseWord := strings.ToLower(word)
		if lowerCaseWord == "kerfuffle" || lowerCaseWord == "sharbert" || lowerCaseWord == "fornax" {
			filteredWords = append(filteredWords, "****")
		} else {
			filteredWords = append(filteredWords, word)
		}
	}

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		UserID: usrId,
		Body:   strings.Join(filteredWords, " "),
	})
	if err != nil {
		log.Printf("Error creating chirp: %s\n", err)
		errorResponce(500, "Something went wrong", w)
		return
	}

	ret := Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}
	jsonResponce(201, ret, w)
}

// POST /api/polka/webhooks
func (cfg *apiConfig) handlePolkaWebHook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		errorResponce(401, "Not authorized", w)
		return
	}
	if apiKey != cfg.polkaKey {
		errorResponce(401, "Not Authorized", w)
		return
	}
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %\ns", err)
		errorResponce(500, "Something went wrong", w)
		return
	}
	if params.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	usrID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		log.Printf("Error parsing userID: %s\n", err.Error())
		errorResponce(500, "Something went wrong", w)
		return
	}
	if err := cfg.dbQueries.SetChirpyRedByID(r.Context(), usrID); err != nil {
		errorResponce(404, "User not found", w)
		return
	}
	w.WriteHeader(204)
}

func jsonResponce(code int, payload interface{}, w http.ResponseWriter) {
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling data")
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

func errorResponce(code int, errorResponce string, w http.ResponseWriter) {
	type errReturn struct {
		Error string `json:"error"`
	}
	ret := errReturn{
		Error: errorResponce,
	}
	data, err := json.Marshal(ret)
	if err != nil {
		log.Printf("Error Marshaling data")
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(data)
}

func main() {
	apiCfg := apiConfig{}
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	apiCfg.platform = os.Getenv("PLATFORM")
	apiCfg.secret = os.Getenv("SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("error opening db: %s\n", err.Error())
		os.Exit(1)
	}
	apiCfg.dbQueries = database.New(db)

	serverMux := http.NewServeMux()
	serverMux.Handle(
		"/app/",
		http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))),
	)

	serverMux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	serverMux.HandleFunc("POST /api/chirps", apiCfg.handlePostChirp)
	serverMux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	serverMux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	serverMux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)
	serverMux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlePolkaWebHook)

	serverMux.HandleFunc("PUT /api/users", apiCfg.handleUpdateUser)

	serverMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handleDeleteChirp)

	serverMux.HandleFunc("GET /api/chirps", apiCfg.handleGetChirps)
	serverMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleGetChirpByID)

	serverMux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	serverMux.HandleFunc("POST /admin/reset", apiCfg.handleReset)

	serverMux.HandleFunc(
		"GET /api/healthz",
		func(rw http.ResponseWriter, req *http.Request) {
			header := rw.Header()
			header.Add("Content-Type", "text/plain; charset=utf-8")
			rw.WriteHeader(200)
			rw.Write([]byte("OK"))
		},
	)

	server := http.Server{
		Handler: serverMux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
