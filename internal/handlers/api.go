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

// admin
func syncrunsErrorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT top (10) run_name
      ,started_at
      ,finished_at
      ,status
      ,error_message
  FROM Fuel.dbo.SyncRuns
  where status != 'SUCCESS'
  order by started_at desc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on syncrunsErrorHandler: " + err.Error())
		http.Error(w, "query error: "+err.Error(), 500)
		return
	}
	defer rows.Close()

	type rowOut struct {
		RunName      string `json:"RunName"`
		StartedAt    string `json:"StartedAt"`
		FinishedAt   string `json:"FinishedAt"`
		Status       string `json:"Status"`
		ErrorMessage string `json:"ErrorMessage"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			run_name      sql.NullString
			started_at    sql.NullTime
			finished_at   sql.NullTime
			status        sql.NullString
			error_message sql.NullString // Changed from sql.NullTime to sql.NullString
		)
		if err := rows.Scan(&run_name, &started_at, &finished_at, &status, &error_message); err != nil {
			logger.Info("Scan error on syncrunsErrorHandler: " + err.Error())
			http.Error(w, "scan error: "+err.Error(), 500)
			return
		}

		out = append(out, rowOut{
			RunName:      run_name.String,
			StartedAt:    started_at.Time.Format("02/01/2006 15:04"),
			FinishedAt:   finished_at.Time.Format("02/01/2006 15:04"),
			Status:       status.String,
			ErrorMessage: error_message.String,
		})
	}
	if err := rows.Err(); err != nil {
		logger.Info("Rows error on syncrunsErrorHandler: " + err.Error())
		http.Error(w, "rows error: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
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
    Groupe
FROM Fuel.dbo.Chauffeurs
where deletedDate = 'None' or deletedDate = ''
ORDER BY FirstName;
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
		if err := rows.Scan(&opNo, &firstName, &lastName, &grp); err != nil {
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
func cartesAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT Cardid
      ,FirstName
      ,LastName
      ,isBroker
      ,Nom_DispatchGroup
      ,CardNumber
      ,NIP
      ,Expiration
	  ,OilCoName
      ,DateRemise
      ,DateReprise
      ,Active
      ,notes
  FROM Fuel.dbo.listCartes
  order by FirstName;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on vehiculesAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		CardId            int    `json:"CardId"`
		Nom               string `json:"Nom"`
		IsBroker          bool   `json:"IsBroker"`
		Nom_DispatchGroup string `json:"Nom_DispatchGroup"`
		CardNumber        string `json:"CardNumber"`
		NIP               string `json:"NIP"`
		Expiration        string `json:"Expiration"`
		OilCoName         string `json:"OilCoName"`
		DateRemise        string `json:"DateRemise"`
		DateReprise       string `json:"DateReprise"`
		Active            bool   `json:"Active"`
		Notes             string `json:"Notes"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			CardId            sql.NullInt32
			FirstName         sql.NullString
			LastName          sql.NullString
			IsBroker          sql.NullBool
			Nom_DispatchGroup sql.NullString
			CardNumber        sql.NullString
			NIP               sql.NullString
			Expiration        sql.NullTime
			OilCoName         sql.NullString
			DateRemise        sql.NullTime
			DateReprise       sql.NullTime
			Active            sql.NullBool
			Notes             sql.NullString
		)
		if err := rows.Scan(
			&CardId,
			&FirstName,
			&LastName,
			&IsBroker,
			&Nom_DispatchGroup,
			&CardNumber,
			&NIP,
			&Expiration,
			&OilCoName,
			&DateRemise,
			&DateReprise,
			&Active,
			&Notes); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on vehiculesAllHandler: " + err.Error())
			return
		}

		// Combine first and last names
		nom := strings.TrimSpace(FirstName.String + " " + LastName.String)

		out = append(out, rowOut{
			CardId:            int(CardId.Int32),
			Nom:               nom,
			IsBroker:          IsBroker.Bool,
			Nom_DispatchGroup: Nom_DispatchGroup.String,
			CardNumber:        CardNumber.String,
			NIP:               NIP.String,
			Expiration: func() string {
				if Expiration.Valid {
					return Expiration.Time.Format("02/01/2006")
				} else {
					return ""
				}
			}(),
			OilCoName: OilCoName.String,
			DateRemise: func() string {
				if DateRemise.Valid {
					return DateRemise.Time.Format("02/01/2006")
				} else {
					return ""
				}
			}(),
			DateReprise: func() string {
				if DateReprise.Valid {
					return DateReprise.Time.Format("02/01/2006")
				} else {
					return ""
				}
			}(),
			Active: Active.Bool,
			Notes:  Notes.String,
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

// POST /api/cartes/add
func cartesAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Request body
	type reqBody struct {
		DriverName string  `json:"driverName"`
		CardNumber string  `json:"cardNumber"`
		NIP        string  `json:"NIP"`
		OilCoName  *string `json:"oilCoName"`
		Expiration *string `json:"Expiration"`
		DateRemise *string `json:"DateRemise"`
		Note       *string `json:"Note"`
		CSRF       string  `json:"csrf,omitempty"`
	}
	var body reqBody

	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on cartesAddHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on cartesAddHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// CSRF: header -> body -> cookie
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
		logger.Info("Invalid CSRF token provided to cartesAddHandler")
		respondWithError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	// Generate fresh token
	if newToken, err := csrfManager.GenerateToken(); err == nil {
		csrfManager.SetTokenCookie(w, newToken)
	}

	// Validate required fields
	if strings.TrimSpace(body.DriverName) == "" || strings.TrimSpace(body.CardNumber) == "" || strings.TrimSpace(body.NIP) == "" {
		respondWithError(w, http.StatusBadRequest, "driverName, cardNumber and NIP are required")
		return
	}
	// oilCoName is required because FK_OilCoid is NOT NULL in the DB
	if body.OilCoName == nil || strings.TrimSpace(*body.OilCoName) == "" {
		respondWithError(w, http.StatusBadRequest, "oilCoName is required")
		return
	}

	session := GetSessionInfo(r)
	user := "unknown"
	if session != nil {
		user = session.Username
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on cartesAddHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Resolve driverName -> Drivers.id using FirstName + ' ' + LastName
	var driverId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM Fuel.dbo.Drivers WHERE LTRIM(RTRIM(FirstName + ' ' + LastName)) = @name`, sql.Named("name", strings.TrimSpace(body.DriverName))).Scan(&driverId); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "driver not found")
			return
		}
		logger.Info("QueryRow error on cartesAddHandler (resolve driver): " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Resolve oil co if provided
	var oilCoIdParam interface{}
	if body.OilCoName != nil {
		oc := strings.TrimSpace(*body.OilCoName)
		if oc != "" {
			var oilCoId sql.NullInt64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM Fuel.dbo.OilCo WHERE OilCoName = @name`, sql.Named("name", oc)).Scan(&oilCoId); err != nil {
				if err == sql.ErrNoRows {
					respondWithError(w, http.StatusBadRequest, "oil company not found")
					return
				}
				logger.Info("QueryRow error on cartesAddHandler (resolve oilco): " + err.Error())
				respondWithError(w, http.StatusInternalServerError, "database error")
				return
			}
			if oilCoId.Valid {
				oilCoIdParam = oilCoId.Int64
			} else {
				oilCoIdParam = nil
			}
		} else {
			oilCoIdParam = nil
		}
	} else {
		oilCoIdParam = nil
	}

	// Prepare nullable params
	var expirationParam interface{}
	if body.Expiration != nil {
		s := strings.TrimSpace(*body.Expiration)
		if s != "" {
			expirationParam = s
		} else {
			expirationParam = nil
		}
	} else {
		expirationParam = nil
	}
	var remiseParam interface{}
	if body.DateRemise != nil {
		s := strings.TrimSpace(*body.DateRemise)
		if s != "" {
			remiseParam = s
		} else {
			remiseParam = nil
		}
	} else {
		remiseParam = nil
	}
	var noteParam interface{}
	if body.Note != nil {
		s := strings.TrimSpace(*body.Note)
		if s != "" {
			noteParam = s
		} else {
			noteParam = nil
		}
	} else {
		noteParam = nil
	}

	// DateReprise should be NULL on add

	insertQ := `
SET NOCOUNT ON;
INSERT INTO Fuel.dbo.Cartes (FK_DriverId, CardNumber, NIP, FK_OilCoId, Expiration, DateRemise, DateReprise, Notes)
OUTPUT INSERTED.CardId
VALUES (@driverId, @cardNumber, @nip, @oilCoId, TRY_CONVERT(date, @expiration, 120), TRY_CONVERT(date, @dr, 120), NULL, @notes);
`

	var newId sql.NullInt64
	if err := tx.QueryRowContext(ctx, insertQ,
		sql.Named("driverId", sql.NullInt64{Int64: driverId.Int64, Valid: driverId.Valid}),
		sql.Named("cardNumber", strings.TrimSpace(body.CardNumber)),
		sql.Named("nip", strings.TrimSpace(body.NIP)),
		sql.Named("oilCoId", oilCoIdParam),
		sql.Named("expiration", expirationParam),
		sql.Named("dr", remiseParam),
		sql.Named("notes", noteParam),
	).Scan(&newId); err != nil {
		logger.Info("Insert error on cartesAddHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesAddHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	idVal := 0
	if newId.Valid {
		idVal = int(newId.Int64)
	}

	logger.Info(fmt.Sprintf("User %s added Card CardId=%d CardNumber=%s OperatorNo=%d", user, idVal, body.CardNumber, driverId.Int64))

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "CardId": idVal})
}

// POST /api/cartes/update
func cartesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Read body
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on cartesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	type reqBody struct {
		CardId      int     `json:"CardId"`
		NIP         string  `json:"NIP"`
		DateRemise  *string `json:"DateRemise"`
		DateReprise *string `json:"DateReprise"`
		Notes       *string `json:"Notes"`
		CSRF        string  `json:"csrf,omitempty"`
	}
	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on cartesUpdateHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// CSRF token: try candidates in order (header, body, cookie). Accept first valid.
	var csrfCandidates []string
	if h := r.Header.Get("X-CSRF-Token"); h != "" {
		csrfCandidates = append(csrfCandidates, h)
	}
	if body.CSRF != "" {
		csrfCandidates = append(csrfCandidates, body.CSRF)
	}
	if c, err := r.Cookie("csrf_token"); err == nil {
		if c != nil && c.Value != "" {
			csrfCandidates = append(csrfCandidates, c.Value)
		}
	}

	var validated bool
	for _, candidate := range csrfCandidates {
		if csrfManager.ValidateToken(candidate) {
			validated = true
			break
		}
	}
	if !validated {
		respondWithError(w, http.StatusForbidden, "invalid CSRF token")
		logger.Info("Invalid CSRF token provided to cartesUpdateHandler; tried candidates")
		return
	}

	// Generate fresh token for client
	if newToken, err := csrfManager.GenerateToken(); err == nil {
		csrfManager.SetTokenCookie(w, newToken)
	}

	if body.CardId <= 0 {
		respondWithError(w, http.StatusBadRequest, "invalid CardId")
		return
	}

	session := GetSessionInfo(r)
	user := "unknown"
	if session != nil {
		user = session.Username
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on cartesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Update assumed table Fuel.dbo.Cards (adjust if necessary)
	updateQ := `
UPDATE Fuel.dbo.Cartes
SET NIP = @nip,
	DateRemise = TRY_CONVERT(date, @dr, 103),
	DateReprise = TRY_CONVERT(date, @dre, 103),
	Notes = @notes
WHERE CardId = @cid;
`
	// Prepare nullable params for dates: send NULL when value is nil or empty
	var drParam interface{}
	var dreParam interface{}
	if body.DateRemise != nil {
		s := strings.TrimSpace(*body.DateRemise)
		if s != "" {
			drParam = s
		} else {
			drParam = nil
		}
	} else {
		drParam = nil
	}
	if body.DateReprise != nil {
		s := strings.TrimSpace(*body.DateReprise)
		if s != "" {
			dreParam = s
		} else {
			dreParam = nil
		}
	} else {
		dreParam = nil
	}

	// Prepare nullable param for Notes
	var notesParam interface{}
	if body.Notes != nil {
		ns := strings.TrimSpace(*body.Notes)
		if ns != "" {
			notesParam = ns
		} else {
			notesParam = nil
		}
	} else {
		notesParam = nil
	}

	if _, err := tx.ExecContext(ctx, updateQ,
		sql.Named("nip", strings.TrimSpace(body.NIP)),
		sql.Named("dr", drParam),
		sql.Named("dre", dreParam),
		sql.Named("notes", notesParam),
		sql.Named("cid", body.CardId),
	); err != nil {
		logger.Info("Exec error on cartesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Build log values for dates (empty if nil)
	drLog := ""
	dreLog := ""
	notesLog := ""
	if body.DateRemise != nil {
		drLog = *body.DateRemise
	}
	if body.DateReprise != nil {
		dreLog = *body.DateReprise
	}
	if body.Notes != nil {
		notesLog = *body.Notes
	}
	logger.Info(fmt.Sprintf("User %s updated CardId=%d NIP=%s DateRemise=%s DateReprise=%s Notes=%s", user, body.CardId, body.NIP, drLog, dreLog, notesLog))

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// POST /api/cartes/delete
func cartesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	type reqBody struct {
		CardId     int    `json:"CardId"`
		CardNumber string `json:"CardNumber"`
		Confirm    string `json:"Confirm"` // must equal "SUPPRIMER"
		CSRF       string `json:"csrf,omitempty"`
	}
	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on cartesDeleteHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// CSRF
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
		logger.Info("Invalid CSRF token provided to cartesDeleteHandler")
		respondWithError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	if body.CardId <= 0 || strings.TrimSpace(body.CardNumber) == "" || body.Confirm != "SUPPRIMER" {
		respondWithError(w, http.StatusBadRequest, "confirmation failed")
		return
	}

	session := GetSessionInfo(r)
	user := "unknown"
	if session != nil {
		user = session.Username
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Read the current row from the view so we can log its full data for restores
	var (
		selCardId      sql.NullInt64
		selFirstName   sql.NullString
		selLastName    sql.NullString
		selCardNumber  sql.NullString
		selNIP         sql.NullString
		selExpiration  sql.NullString
		selOilCoName   sql.NullString
		selDateRemise  sql.NullString
		selDateReprise sql.NullString
		selActive      sql.NullBool
		selNotes       sql.NullString
	)

	selQ := `
SELECT CardId, FirstName, LastName, CardNumber, NIP, Expiration, OilCoName, DateRemise, DateReprise, Active, notes
FROM Fuel.dbo.listCartes
WHERE CardId = @cid
`
	if err := tx.QueryRowContext(ctx, selQ, sql.Named("cid", body.CardId)).Scan(
		&selCardId,
		&selFirstName,
		&selLastName,
		&selCardNumber,
		&selNIP,
		&selExpiration,
		&selOilCoName,
		&selDateRemise,
		&selDateReprise,
		&selActive,
		&selNotes,
	); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "card not found")
			return
		}
		logger.Info("QueryRow error on cartesDeleteHandler (select): " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Build a JSON payload of the row for logging (for potential restore)
	backup := map[string]interface{}{
		"CardId":      int(selCardId.Int64),
		"FirstName":   selFirstName.String,
		"LastName":    selLastName.String,
		"CardNumber":  selCardNumber.String,
		"NIP":         selNIP.String,
		"Expiration":  selExpiration.String,
		"OilCoName":   selOilCoName.String,
		"DateRemise":  selDateRemise.String,
		"DateReprise": selDateReprise.String,
		"Active":      selActive.Bool,
		"Notes":       selNotes.String,
	}
	if jb, err := json.Marshal(backup); err == nil {
		logger.Info("[DELETE BACKUP] " + string(jb))
	} else {
		logger.Info("Failed to marshal delete backup: " + err.Error())
	}

	// Attempt physical delete from table
	delQ := `DELETE FROM Fuel.dbo.Cartes WHERE CardId = @cid AND CardNumber = @cn;`
	if res, err := tx.ExecContext(ctx, delQ, sql.Named("cid", body.CardId), sql.Named("cn", body.CardNumber)); err != nil {
		logger.Info("Exec error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	} else {
		if ra, _ := res.RowsAffected(); ra == 0 {
			respondWithError(w, http.StatusBadRequest, "no rows deleted")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error")
		return
	}

	logger.Info(fmt.Sprintf("User %s deleted CardId=%d CardNumber=%s", user, body.CardId, body.CardNumber))

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
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
