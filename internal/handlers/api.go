package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	IsAdmin  bool
}

func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

func AuthenticateUser(db *sql.DB, username, password string) (*User, error) {
	u := normalizeUsername(username)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		id      int
		hash    string
		isAdmin bool
	)

	err := db.QueryRowContext(ctx, `
        SELECT id, password_hash, isAdmin
        FROM dbo.SiteUser
        WHERE SiteUser=@u
    `, sql.Named("u", u)).Scan(&id, &hash, &isAdmin)

	if err == sql.ErrNoRows {
		// Ne divulgue pas si l'utilisateur existe ou non
		return nil, errors.New("invalid credentials")
	}
	if err != nil {
		return nil, err
	}

	// Compare le hash bcrypt
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}

	return &User{
		ID:       id,
		Username: u,
		IsAdmin:  isAdmin,
	}, nil
}

// /api/chauffeurs
// GET /api/chauffeurs/all
func chauffeursAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT
    operatorNo,
    FirstName,
    LastName,
    Groupe,
    startDate
FROM Fuel.dbo.Chauffeurs
ORDER BY operatorNo;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on chauffeursAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		OperatorNo string `json:"operatorNo"`
		Nom        string `json:"Nom"`
		Groupe     string `json:"Groupe"`
		StartDate  string `json:"startDate"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			opNo      sql.NullString
			firstName sql.NullString
			lastName  sql.NullString
			grp       sql.NullString
			sd        sql.NullString // Changed from sql.NullTime to sql.NullString
		)
		if err := rows.Scan(&opNo, &firstName, &lastName, &grp, &sd); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on chauffeursAllHandler: " + err.Error())
			return
		}

		// Combine first and last names
		nom := strings.TrimSpace(firstName.String + " " + lastName.String)

		// Trim date to YYYY-MM-DD format (remove time portion if present)
		startDate := sd.String
		if len(startDate) > 10 {
			startDate = startDate[:10]
		}

		out = append(out, rowOut{
			OperatorNo: opNo.String,
			Nom:        nom,
			Groupe:     grp.String,
			StartDate:  startDate,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on chauffeursAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func petrolieresAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT
    OilCoName,
	Compte
FROM Fuel.dbo.OilCo
ORDER BY OilCoName;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on petrolieresAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		OilCoName string `json:"OilCoName"`
		Compte    string `json:"Compte"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			OilCoName sql.NullString
			Compte    sql.NullString
		)
		if err := rows.Scan(&OilCoName, &Compte); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on petrolieresAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			OilCoName: OilCoName.String,
			Compte:    Compte.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on petrolieresAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func vehiculesAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT unitNumber
    ,unitLicenceNumber
	,IsUsable
	,UnitDescription
	,unitIsIFTAPlated
	,unitProvince
	,unitFuelType
	,GL
	,NomCommunGl
FROM Fuel.dbo.unitListWithGL
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on vehiculesAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		UnitNumber       string `json:"unitNumber"`
		Plaque           string `json:"unitLicenceNumber"`
		IsUsable         bool   `json:"isUsable"`
		UnitDescription  string `json:"unitDescription"`
		UnitIsIFTAPlated string `json:"unitIsIFTAPlated"`
		UnitProvince     string `json:"unitProvince"`
		UnitFuelType     string `json:"unitFuelType"`
		Gl               string `json:"GL"`
		NomCommunGL      string `json:"nomCommunGL"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			UnitNumber       sql.NullString
			Plaque           sql.NullString
			IsUsable         sql.NullBool
			UnitDescription  sql.NullString
			UnitIsIFTAPlated sql.NullString
			UnitProvince     sql.NullString
			UnitFuelType     sql.NullString
			Gl               sql.NullString
			NomCommunGL      sql.NullString
		)
		if err := rows.Scan(&UnitNumber, &Plaque, &IsUsable, &UnitDescription, &UnitIsIFTAPlated, &UnitProvince, &UnitFuelType, &Gl, &NomCommunGL); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on vehiculesAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			UnitNumber:       UnitNumber.String,
			Plaque:           Plaque.String,
			IsUsable:         IsUsable.Bool,
			UnitDescription:  UnitDescription.String,
			UnitIsIFTAPlated: UnitIsIFTAPlated.String,
			UnitProvince:     UnitProvince.String,
			UnitFuelType:     UnitFuelType.String,
			Gl:               Gl.String,
			NomCommunGL:      NomCommunGL.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on vehiculesAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
