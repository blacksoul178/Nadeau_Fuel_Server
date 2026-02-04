package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
func brokersAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT id, Nom_Commun, Nom_Legal, Acomba
FROM Fuel.dbo.BrokerCo
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on brokersAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Id         int    `json:"id"`
		Nom_Commun string `json:"Nom_Commun"`
		Nom_Legal  string `json:"Nom_Legal"`
		Acomba     string `json:"Acomba"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Id         sql.NullInt32
			Nom_Commun sql.NullString
			Nom_Legal  sql.NullString
			Acomba     sql.NullString
		)
		if err := rows.Scan(&Id, &Nom_Commun, &Nom_Legal, &Acomba); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on brokersAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Id:         int(Id.Int32),
			Nom_Commun: Nom_Commun.String,
			Nom_Legal:  Nom_Legal.String,
			Acomba:     Acomba.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on brokersAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func brokersAddDriver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Parse request JSON (includes optional csrf token in body)
	type reqBody struct {
		BrokerId      int    `json:"brokerId"`
		BrokerName    string `json:"brokerName"`
		DispatchGroup int    `json:"dispatchGroup"`
		StartDate     string `json:"startDate"`
		CSRF          string `json:"csrf,omitempty"`
	}
	var body reqBody

	// Read raw body for diagnostics
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	logger.Info("brokersAddDriver raw body: " + string(b))
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on brokersAddDriver: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	logger.Info(fmt.Sprintf("brokersAddDriver parsed body: brokerId=%d brokerName=%q dispatchGroup=%d startDate=%q", body.BrokerId, body.BrokerName, body.DispatchGroup, body.StartDate))

	// Determine CSRF token: header -> body -> cookie
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" && body.CSRF != "" {
		csrf = body.CSRF
	}
	if csrf == "" {
		if c, err := r.Cookie("csrf_token"); err == nil {
			csrf = c.Value
		}
	}
	if csrf == "" {
		respondWithError(w, http.StatusForbidden, "missing CSRF token")
		return
	}
	if !csrfManager.ValidateToken(csrf) {
		logger.Info("Invalid CSRF token provided to brokersAddDriver")
		respondWithError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	// Generate and set a fresh token for subsequent requests
	if newToken, err := csrfManager.GenerateToken(); err == nil {
		csrfManager.SetTokenCookie(w, newToken)
	} else {
		logger.Info("Failed to generate CSRF token after brokersAddDriver: " + err.Error())
	}

	if body.BrokerId <= 0 || strings.TrimSpace(body.BrokerName) == "" {
		respondWithError(w, http.StatusBadRequest, "invalid broker payload")
		return
	}
	if body.StartDate == "" {
		respondWithError(w, http.StatusBadRequest, "startDate required")
		return
	}

	// Start transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Verify broker exists
	var existingName sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT Nom_Commun FROM Fuel.dbo.BrokerCo WHERE id = @id`, sql.Named("id", body.BrokerId)).Scan(&existingName); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "broker not found")
			return
		}
		logger.Info("Query error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Determine next LastName (numeric suffix)
	var maxSuffix sql.NullInt64
	// Use TRY_CAST to safely convert LastName to int; unsupported DB will return NULL and ISNULL will give 0
	if err := tx.QueryRowContext(ctx, `
		SELECT ISNULL(MAX(TRY_CAST(LastName AS INT)), 0) FROM Fuel.dbo.Drivers WHERE FirstName = @fname
	`, sql.Named("fname", body.BrokerName)).Scan(&maxSuffix); err != nil {
		logger.Info("Query error on brokersAddDriver (max suffix): " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	next := 1
	if maxSuffix.Valid {
		next = int(maxSuffix.Int64) + 1
	}
	lastName := strconv.Itoa(next)
	operatorNo := strings.TrimSpace(body.BrokerName + " " + lastName)

	// Insert driver and return new ID using OUTPUT
	insertQ := `
	SET NOCOUNT ON;
	INSERT INTO Fuel.dbo.Drivers (operatorNo, FirstName, LastName, FK_DispatchGroup, startDate, isBroker, FK_BrokerId)
	OUTPUT INSERTED.id
	VALUES (@operatorNo, @FirstName, @LastName, @FK_DispatchGroup, @startDate, @isBroker, @FK_BrokerId);
	`
	var newId sql.NullInt64
	if err := tx.QueryRowContext(ctx, insertQ,
		sql.Named("operatorNo", operatorNo),
		sql.Named("FirstName", body.BrokerName),
		sql.Named("LastName", lastName),
		sql.Named("FK_DispatchGroup", body.DispatchGroup),
		sql.Named("startDate", body.StartDate),
		sql.Named("isBroker", 1),
		sql.Named("FK_BrokerId", body.BrokerId),
	).Scan(&newId); err != nil {
		logger.Info("Insert error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	logger.Info(fmt.Sprintf("brokersAddDriver inserted id (tx): %v", newId))

	// Verify insertion
	var verifyId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT TOP 1 id FROM Fuel.dbo.Drivers WHERE operatorNo = @op AND FK_BrokerId = @bid ORDER BY id DESC`, sql.Named("op", operatorNo), sql.Named("bid", body.BrokerId)).Scan(&verifyId); err != nil {
		if err == sql.ErrNoRows {
			logger.Info("Verification select: no rows found after insert for operatorNo=" + operatorNo)
		} else {
			logger.Info("Verification select error on brokersAddDriver: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "database error")
			return
		}
	} else {
		logger.Info(fmt.Sprintf("Verification select found id: %v", verifyId))
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	res := map[string]interface{}{
		"id":         nil,
		"operatorNo": operatorNo,
		"firstName":  body.BrokerName,
		"lastName":   lastName,
	}
	if newId.Valid {
		res["id"] = int(newId.Int64)
	}

	respondWithJSON(w, http.StatusOK, res)
}
func brokersAddCo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Parse request JSON (includes optional csrf token in body)
	type reqBody struct {
		BrokerCoCommonName string `json:"brokerCoCommonName"`
		BrokerCoLegalName  string `json:"brokerCoLegalName"`
		BrokerCoAcomba     string `json:"brokerCoAcomba"`
		CSRF               string `json:"csrf,omitempty"`
	}
	var body reqBody

	// Read raw body for diagnostics
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on brokersAddCo: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	logger.Info("brokersAddCo raw body: " + string(b))
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on brokersAddCo: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	logger.Info(fmt.Sprintf("brokersAddCo parsed body: brokerCoCommonName=%s brokerCoLegalName=%s brokerCoAcomba=%s", body.BrokerCoCommonName, body.BrokerCoLegalName, body.BrokerCoAcomba))

	// Determine CSRF token: header -> body -> cookie
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" && body.CSRF != "" {
		csrf = body.CSRF
	}
	if csrf == "" {
		if c, err := r.Cookie("csrf_token"); err == nil {
			csrf = c.Value
		}
	}
	if csrf == "" {
		respondWithError(w, http.StatusForbidden, "missing CSRF token")
		return
	}
	if !csrfManager.ValidateToken(csrf) {
		logger.Info("Invalid CSRF token provided to brokersAddCo")
		respondWithError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	// Generate and set a fresh token for subsequent requests
	if newToken, err := csrfManager.GenerateToken(); err == nil {
		csrfManager.SetTokenCookie(w, newToken)
	} else {
		logger.Info("Failed to generate CSRF token after brokersAddCo: " + err.Error())
	}

	if len(body.BrokerCoCommonName) == 0 || strings.TrimSpace(body.BrokerCoCommonName) == "" {
		respondWithError(w, http.StatusBadRequest, "invalid broker Common Name")
		return
	}
	if len(body.BrokerCoLegalName) == 0 {
		respondWithError(w, http.StatusBadRequest, "invalid broker legal name")
		return
	}

	// Start transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on brokersAddCo: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Insert driver and return new ID using OUTPUT
	insertQ := `
	SET NOCOUNT ON;
	INSERT INTO Fuel.dbo.BrokerCo (Nom_Legal, Nom_Commun, Acomba)
	OUTPUT INSERTED.id
	VALUES (@Nom_Legal, @Nom_Commun, @Acomba);
	`
	var newId sql.NullInt64
	if err := tx.QueryRowContext(ctx, insertQ,
		sql.Named("Nom_Legal", body.BrokerCoLegalName),
		sql.Named("Nom_Commun", body.BrokerCoCommonName),
		sql.Named("Acomba", body.BrokerCoAcomba),
	).Scan(&newId); err != nil {
		logger.Info("Insert error on brokersAddCo: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	logger.Info(fmt.Sprintf("brokersAddCo inserted id (tx): %v", newId))

	// Verify insertion
	var verifyId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT TOP 1 id FROM Fuel.dbo.BrokerCo WHERE Nom_Legal = @nl and Nom_Commun = @nc and Acomba = @A`, sql.Named("nl", body.BrokerCoLegalName), sql.Named("nc", body.BrokerCoCommonName), sql.Named("A", body.BrokerCoAcomba)).Scan(&verifyId); err != nil {
		if err == sql.ErrNoRows {
			logger.Info("Verification select: no rows found after insert for Nom_Commun" + body.BrokerCoCommonName)
		} else {
			logger.Info("Verification select error on brokersAddCo: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "database error")
			return
		}
	} else {
		logger.Info(fmt.Sprintf("Verification select found id: %v", verifyId))
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	res := map[string]interface{}{
		"id":                 nil,
		"brokerCoCommonName": body.BrokerCoCommonName,
		"brokerCoLegalName":  body.BrokerCoLegalName,
		"BrokerCoAcomba":     body.BrokerCoAcomba,
	}
	if newId.Valid {
		res["id"] = int(newId.Int64)
	}

	respondWithJSON(w, http.StatusOK, res)
}
