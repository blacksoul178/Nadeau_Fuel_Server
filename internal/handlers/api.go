package handlers

// All API Handlers
import (
	"Nadeau_Fuel_Server/internal/logger"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//tools functions

func round2(v float64) float64 { //round to 2 decimals
	return math.Round(v*100) / 100
}

type User struct {
	ID          int
	Username    string
	IsAdmin     bool
	IsSuperUser bool
}

func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}
func AuthenticateUser(db *sql.DB, username, password string) (*User, error) {
	u := normalizeUsername(username)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		id          int
		hash        string
		isAdmin     bool
		isSuperUser bool
		isDisabled  bool
	)

	err := db.QueryRowContext(ctx, `
		SELECT id, password_hash, isAdmin, isSuperUser, isDisabled
		FROM dbo.AppUser
		WHERE AppUser=@u
	`, sql.Named("u", u)).Scan(&id, &hash, &isAdmin, &isSuperUser, &isDisabled)

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

	// Check if user is disabled
	if isDisabled {
		return nil, errors.New("user account is disabled")
	}
	return &User{

		ID:          id,
		Username:    u,
		IsAdmin:     isAdmin,
		IsSuperUser: isSuperUser,
	}, nil
}

// admin fetch Data
func syncrunsAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT run_name
      ,started_at
      ,finished_at
      ,status
      ,error_message
  FROM dbo.SyncRuns
  order by started_at desc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on syncrunsAllHandler: " + err.Error())
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
		logger.Info("Rows error on syncrunsAllHandler: " + err.Error())
		http.Error(w, "rows error: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func logsApiHandler(w http.ResponseWriter, r *http.Request) {

	var logFilePath = `server.log`

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// how many lines to return (default 500, max 10000)
	n := 500
	if s := r.URL.Query().Get("last"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 10000 {
			n = v
		}
	}

	data, err := os.ReadFile(logFilePath)
	if err != nil {
		// keep it JSON so your fetch().json() doesn't fail
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   true,
			"message": "failed to read log file",
			"details": err.Error(),
		})
		return
	}

	// Split into lines (handle Windows \r\n and final trailing line)
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	// Drop a trailing empty line if present
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// Take last n lines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	// Reverse so newest appears first
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	_ = json.NewEncoder(w).Encode(lines)
}
func usersAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := `SELECT id, AppUser, IsAdmin, IsSuperUser, IsDisabled FROM dbo.AppUser ORDER BY AppUser`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on usersAllHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}
	defer rows.Close()

	type userOut struct {
		Id          int    `json:"id"`
		AppUser     string `json:"AppUser"`
		IsAdmin     bool   `json:"IsAdmin"`
		IsSuperUser bool   `json:"IsSuperUser"`
		IsDisabled  bool   `json:"IsDisabled"`
	}

	out := make([]userOut, 0, 256)

	for rows.Next() {
		var (
			id          sql.NullInt32
			AppUser     sql.NullString
			isAdmin     sql.NullBool
			isSuperUser sql.NullBool
			isDisabled  sql.NullBool
		)
		if err := rows.Scan(&id, &AppUser, &isAdmin, &isSuperUser, &isDisabled); err != nil {
			logger.Info("Scan error on usersAllHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Scan error")
			return
		}

		out = append(out, userOut{
			Id:          int(id.Int32),
			AppUser:     AppUser.String,
			IsAdmin:     isAdmin.Bool,
			IsSuperUser: isSuperUser.Bool,
			IsDisabled:  isDisabled.Bool,
		})
	}

	if err := rows.Err(); err != nil {
		logger.Info("Rows error on usersAllHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Rows error")
		return
	}

	if out == nil {
		out = []userOut{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// GETs fetch data
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
	isBroker
FROM dbo.Chauffeurs
WHERE
    deletedDate IS NULL
    OR LTRIM(RTRIM(deletedDate)) = ''
    OR UPPER(LTRIM(RTRIM(deletedDate))) IN ('NULL', 'NONE')
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
		IsBroker   bool   `json:"isBroker"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			opNo      sql.NullString
			firstName sql.NullString
			lastName  sql.NullString
			grp       sql.NullString
			sd        sql.NullString // Changed from sql.NullTime to sql.NullString
			isBroker  sql.NullBool
		)
		if err := rows.Scan(&opNo, &firstName, &lastName, &grp, &isBroker); err != nil {
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
			IsBroker:   isBroker.Bool,
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
func chauffeursPretHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
select operatorNo, Groupe
FROM dbo.chauffeurs d
WHERE d.pret = 1
        AND NOT EXISTS (
            SELECT 1
            FROM dbo.Cartes c
            WHERE c.fk_driverId = d.id
        )


ORDER BY FirstName;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on chauffeursPretHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		OperatorNo string `json:"operatorNo"`
		Groupe     string `json:"Groupe"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			opNo sql.NullString
			grp  sql.NullString
		)
		if err := rows.Scan(&opNo, &grp); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on chauffeursPretHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			OperatorNo: opNo.String,
			Groupe:     grp.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on chauffeursPretHandler: " + err.Error())
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
  FROM dbo.listCartes
  order by FirstName;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on cartesAllHandler: " + err.Error())
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
			logger.Info("Scan error on cartesAllHandler: " + err.Error())
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
		logger.Info("Rows error on cartesAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func cartesPretAllHandler(w http.ResponseWriter, r *http.Request) {
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
  FROM dbo.listCartes
  where pret = 1
  order by FirstName;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on cartesPretAllHandler: " + err.Error())
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
			logger.Info("Scan error on cartesPretAllHandler: " + err.Error())
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
		logger.Info("Rows error on cartesPretAllHandler: " + err.Error())
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
	Compte,
	Banner
FROM dbo.OilCo
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
		Banner    string `json:"Banner"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			OilCoName sql.NullString
			Compte    sql.NullString
			Banner    sql.NullString
		)
		if err := rows.Scan(&OilCoName, &Compte, &Banner); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on petrolieresAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			OilCoName: OilCoName.String,
			Compte:    Compte.String,
			Banner:    Banner.String,
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
	,Propriétaire
	,Ref
FROM dbo.unitListWithGL
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
		Propriétaire     string `json:"Propriétaire"`
		Ref              string `json:"Ref"`
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
			Propriétaire     sql.NullString
			Ref              sql.NullString
		)
		if err := rows.Scan(&UnitNumber, &Plaque, &IsUsable, &UnitDescription, &UnitIsIFTAPlated, &UnitProvince, &UnitFuelType, &Gl, &NomCommunGL, &Propriétaire, &Ref); err != nil {
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
			Propriétaire:     Propriétaire.String,
			Ref:              Ref.String,
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
FROM dbo.BrokerCo
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
func transactionsAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT run_name
      ,started_at
      ,finished_at
      ,status
      ,error_message
      ,total_lines
	  ,total_imported
	  ,total_failures
	  ,duplicate_ids
	  ,missing_card_ids
	  ,other_failures
  FROM dbo.TransactionRuns

  order by started_at desc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on transactionsAllHandler: " + err.Error())
		http.Error(w, "query error: "+err.Error(), 500)
		return
	}
	defer rows.Close()

	type rowOut struct {
		RunName       string `json:"RunName"`
		StartedAt     string `json:"StartedAt"`
		FinishedAt    string `json:"FinishedAt"`
		Status        string `json:"Status"`
		ErrorMessage  string `json:"ErrorMessage"`
		TotalLines    string `json:"TotalLines"`
		Imported      string `json:"Imported"`
		Failures      string `json:"Failures"`
		Duplicates    string `json:"Duplicates"`
		Missing       string `json:"Missing"`
		OtherFailures string `json:"OtherFailures"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			run_name         sql.NullString
			started_at       sql.NullTime
			finished_at      sql.NullTime
			status           sql.NullString
			error_message    sql.NullString
			total_lines      sql.NullString
			total_imported   sql.NullString
			total_failures   sql.NullString
			duplicate_ids    sql.NullString
			missing_card_ids sql.NullString
			other_failures   sql.NullString
		)
		if err := rows.Scan(&run_name, &started_at, &finished_at, &status, &error_message, &total_lines, &total_imported, &total_failures, &duplicate_ids, &missing_card_ids, &other_failures); err != nil {
			logger.Info("Scan error on transactionsAllHandler: " + err.Error())
			http.Error(w, "scan error: "+err.Error(), 500)
			return
		}

		out = append(out, rowOut{
			RunName:       run_name.String,
			StartedAt:     started_at.Time.Format("02/01/2006 15:04"),
			FinishedAt:    finished_at.Time.Format("02/01/2006 15:04"),
			Status:        status.String,
			ErrorMessage:  error_message.String,
			TotalLines:    total_lines.String,
			Imported:      total_imported.String,
			Failures:      total_failures.String,
			Duplicates:    duplicate_ids.String,
			Missing:       missing_card_ids.String,
			OtherFailures: other_failures.String,
		})
	}
	if err := rows.Err(); err != nil {
		logger.Info("Rows error on transactionsAllHandler: " + err.Error())
		http.Error(w, "rows error: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func tauxAllWeekHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (52)
    Annee, Semaine, PrixMoyen_AllPetro
FROM
dbo.v_PrixFuel_Avg_Semaine_All
order by Annee, Semaine desc
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on TauxAllWeekHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee     string `json:"Annee"`
		Semaine   string `json:"Semaine"`
		PrixMoyen string `json:"PrixMoyen"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee     sql.NullString
			Semaine   sql.NullString
			PrixMoyen sql.NullString
		)
		if err := rows.Scan(&Annee, &Semaine, &PrixMoyen); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on TauxAllWeekHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:     Annee.String,
			Semaine:   Semaine.String,
			PrixMoyen: PrixMoyen.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on TauxAllWeekHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelGlobalSemaineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (52) [Annee]
      ,[Semaine]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_Diff_GlobalSemaine]
  order by Annee, Semaine desc
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelGlobalSemaineHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee         string  `json:"Annee"`
		Semaine       string  `json:"Semaine"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee         sql.NullString
			Semaine       sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Annee,
			&Semaine,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on prixFuelGlobalSemaineHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:         Annee.String,
			Semaine:       Semaine.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelGlobalSemaineHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelGlobalJourHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (365) [Date]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_Diff_GlobalJour]
  order by [Date] desc
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelGlobalJourHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date          string  `json:"Date"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date          sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Date,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelGlobalJourlHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:          Date.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelGlobalJourHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelDiffSemaineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Annee]
      ,[Semaine]
      ,[Ville]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_Diff_semaine]
  order by Annee, Semaine desc

`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelDiffSemaineHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee         string  `json:"Annee"`
		Semaine       string  `json:"Semaine"`
		Ville         string  `json:"Ville"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee         sql.NullString
			Semaine       sql.NullString
			Ville         sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Annee,
			&Semaine,
			&Ville,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on prixFuelDiffSemaineHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:         Annee.String,
			Semaine:       Semaine.String,
			Ville:         Ville.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelDiffSemaineHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelDiffJourHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Date]
      ,[Ville]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_Diff_Jour]
  Order by [date] desc
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelDiffJourHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date          string  `json:"Date"`
		Ville         string  `json:"Ville"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date          sql.NullString
			Ville         sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Date,
			&Ville,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelDiffJourHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:          Date.String,
			Ville:         Ville.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelDiffJourHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelDiffRegionSemaineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Annee]
      ,[Semaine]
      ,[Region]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_DiffRegionSemaine]
  order by Annee desc, Semaine desc, Region asc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelDiffRegionSemaineHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee         string  `json:"Annee"`
		Semaine       string  `json:"Semaine"`
		Region        string  `json:"Region"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee         sql.NullString
			Semaine       sql.NullString
			Region        sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Annee,
			&Semaine,
			&Region,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on prixFuelDiffRegionSemaineHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:         Annee.String,
			Semaine:       Semaine.String,
			Region:        Region.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelDiffRegionSemaineHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelDiffRegionJourHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Date]
      ,[Region]
      ,[Prix_Harnois]
      ,[Diff_Esso] * 100
      ,[Diff_Petro] * 100
      ,[Diff_Ultramar] * 100
      ,[Diff_Irving] * 100
      ,[Diff_Belisle] * 100
  FROM [dbo].[v_PrixFuel_DiffRegionJour]
  order by [date] desc, Region asc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelDiffRegionJourHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date          string  `json:"Date"`
		Region        string  `json:"Region"`
		Prix_Harnois  string  `json:"Prix_Harnois"`
		Diff_Esso     float64 `json:"Diff_Esso"`
		Diff_Petro    float64 `json:"Diff_Petro"`
		Diff_Ultramar float64 `json:"Diff_Ultramar"`
		Diff_Irving   float64 `json:"Diff_Irving"`
		Diff_Belisle  float64 `json:"Diff_Belisle"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date          sql.NullString
			Region        sql.NullString
			Prix_Harnois  sql.NullString
			Diff_Esso     sql.NullFloat64
			Diff_Petro    sql.NullFloat64
			Diff_Ultramar sql.NullFloat64
			Diff_Irving   sql.NullFloat64
			Diff_Belisle  sql.NullFloat64
		)
		if err := rows.Scan(
			&Date,
			&Region,
			&Prix_Harnois,
			&Diff_Esso,
			&Diff_Petro,
			&Diff_Ultramar,
			&Diff_Irving,
			&Diff_Belisle,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelDiffRegionJourHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:          Date.String,
			Region:        Region.String,
			Prix_Harnois:  Prix_Harnois.String,
			Diff_Esso:     Diff_Esso.Float64,
			Diff_Petro:    Diff_Petro.Float64,
			Diff_Ultramar: Diff_Ultramar.Float64,
			Diff_Irving:   Diff_Irving.Float64,
			Diff_Belisle:  Diff_Belisle.Float64,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelDiffRegionJourHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelSemaineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT [Annee]
      ,[Semaine]
      ,[Petroliere]
      ,[Ville]
      ,[PrixMoyen]
  FROM [dbo].[v_PrixFuel_semaine]
  order by Annee, Semaine desc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelSemaineHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee      string `json:"Annee"`
		Semaine    string `json:"Semaine"`
		Petroliere string `json:"Petroliere"`
		Ville      string `json:"Ville"`
		PrixMoyen  string `json:"PrixMoyen"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee      sql.NullString
			Semaine    sql.NullString
			Petroliere sql.NullString
			Ville      sql.NullString
			PrixMoyen  sql.NullString
		)
		if err := rows.Scan(
			&Annee,
			&Semaine,
			&Petroliere,
			&Ville,
			&PrixMoyen,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelSemaineHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:      Annee.String,
			Semaine:    Semaine.String,
			Petroliere: Petroliere.String,
			Ville:      Ville.String,
			PrixMoyen:  PrixMoyen.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelSemaineHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelJourHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT [Date]
      ,[Petroliere]
      ,[Ville]
      ,[PrixMoyen]
  FROM [dbo].[v_PrixFuel_Jour]
  order by [Date] Desc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelJourHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date       string `json:"Date"`
		Petroliere string `json:"Petroliere"`
		Ville      string `json:"Ville"`
		PrixMoyen  string `json:"PrixMoyen"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date       sql.NullString
			Petroliere sql.NullString
			Ville      sql.NullString
			PrixMoyen  sql.NullString
		)
		if err := rows.Scan(
			&Date,
			&Petroliere,
			&Ville,
			&PrixMoyen,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelJourHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:       Date.String,
			Petroliere: Petroliere.String,
			Ville:      Ville.String,
			PrixMoyen:  PrixMoyen.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelJourHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelRegionSemaineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Annee]
      ,[Semaine]
      ,[Region]
      ,[Petroliere]
      ,[PrixMoyen]
  FROM [dbo].[v_PrixFuel_RegionSemaine]
  order by Annee desc, Semaine desc, Region asc;
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelRegionSemaineHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Annee      string `json:"Annee"`
		Semaine    string `json:"Semaine"`
		Petroliere string `json:"Petroliere"`
		Region     string `json:"Region"`
		PrixMoyen  string `json:"PrixMoyen"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Annee      sql.NullString
			Semaine    sql.NullString
			Petroliere sql.NullString
			Region     sql.NullString
			PrixMoyen  sql.NullString
		)
		if err := rows.Scan(
			&Annee,
			&Semaine,
			&Petroliere,
			&Region,
			&PrixMoyen,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelRegionSemaineHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Annee:      Annee.String,
			Semaine:    Semaine.String,
			Petroliere: Petroliere.String,
			Region:     Region.String,
			PrixMoyen:  PrixMoyen.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelRegionSemaineHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func prixFuelRegionJourHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
SELECT TOP (1000) [Date]
      ,[Region]
      ,[Petroliere]
      ,[PrixMoyen]
  FROM [dbo].[v_PrixFuel_RegionJour]
  order by [Date] desc, Region asc
`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on PrixFuelRegionJourHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date       string `json:"Date"`
		Petroliere string `json:"Petroliere"`
		Region     string `json:"Region"`
		PrixMoyen  string `json:"PrixMoyen"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date       sql.NullString
			Petroliere sql.NullString
			Region     sql.NullString
			PrixMoyen  sql.NullString
		)
		if err := rows.Scan(
			&Date,
			&Petroliere,
			&Region,
			&PrixMoyen,
		); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on PrixFuelRegionJourHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:       Date.String,
			Petroliere: Petroliere.String,
			Region:     Region.String,
			PrixMoyen:  PrixMoyen.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on PrixFuelRegionJourHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func syncStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := `
	SELECT
		FK_OilCoId,
		Compte,
		OilCoName,
		DerniereSynchro,
		DerniereTransaction,
		JoursDeRetard,
		Note
	FROM dbo.DerniereSynchroComplete
	where OilCoName != 'Traversiers'
	ORDER BY FK_OilCoId ASC
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on syncStatusHandler: " + err.Error())
		http.Error(w, "query error: "+err.Error(), 500)
		return
	}
	defer rows.Close()

	type SyncStatus struct {
		OilCoID             int    `json:"OilCoID"`
		Compte              string `json:"Compte"`
		OilCoName           string `json:"OilCoName"`
		DerniereSynchro     string `json:"DerniereSynchro"`
		DerniereTransaction string `json:"DerniereTransaction"`
		JoursDeRetard       int    `json:"JoursDeRetard"`
		Note                string `json:"Note"`
	}
	out := make([]SyncStatus, 0, 256)

	for rows.Next() {
		var (
			oilCoId             sql.NullInt64
			compte              sql.NullString
			oilCoName           sql.NullString
			derniereSynchro     sql.NullTime
			derniereTransaction sql.NullTime
			joursDeRetard       sql.NullInt64
			note                sql.NullString
		)
		if err := rows.Scan(&oilCoId, &compte, &oilCoName, &derniereSynchro, &derniereTransaction, &joursDeRetard, &note); err != nil {
			logger.Info("Scan error on syncStatusHandler: " + err.Error())
			http.Error(w, "scan error: "+err.Error(), 500)
			return
		}

		syncStatus := SyncStatus{
			OilCoID:   int(oilCoId.Int64),
			Compte:    compte.String,
			OilCoName: oilCoName.String,
			Note:      note.String,
		}

		if derniereSynchro.Valid {
			syncStatus.DerniereSynchro = derniereSynchro.Time.Format("2006-01-02T15:04:05")
		}

		if derniereTransaction.Valid {
			syncStatus.DerniereTransaction = derniereTransaction.Time.Format("2006-01-02T15:04:05")
		}

		if joursDeRetard.Valid {
			syncStatus.JoursDeRetard = int(joursDeRetard.Int64)
		}

		out = append(out, syncStatus)
	}

	if err := rows.Err(); err != nil {
		logger.Info("Rows error on syncStatusHandler: " + err.Error())
		http.Error(w, "rows error: "+err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func updateNoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type UpdateNoteRequest struct {
		OilcoId int    `json:"oilcoId"`
		Note    string `json:"note"`
	}

	var req UpdateNoteRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	query := `
	UPDATE dbo.OilCo
	SET note = @note
	WHERE id = @id
	`

	result, err := db.ExecContext(ctx, query, sql.Named("note", req.Note), sql.Named("id", req.OilcoId))
	if err != nil {
		logger.Info("Update error on updateNoteHandler: " + err.Error())
		http.Error(w, "update error: "+err.Error(), 500)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Info("RowsAffected error on updateNoteHandler: " + err.Error())
		http.Error(w, "rows affected error: "+err.Error(), 500)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "no rows updated", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Note updated successfully"})
}

func villesAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
	SELECT 
	SupplierCity, NormalizedCity, Region,
	LastUpdatedBy, LastUpdatedDate
	FROM dbo.CityNormalization
	ORDER BY
    CASE WHEN NormalizedCity IS NULL THEN 0 ELSE 1 END,  -- NULLs first
    LastUpdatedDate DESC;
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on villesAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		SupplierCity    string `json:"SupplierCity"`
		NormalizedCity  string `json:"NormalizedCity"`
		Region          string `json:"Region"`
		LastUpdatedBy   string `json:"LastUpdatedBy"`
		LastUpdatedDate string `json:"LastUpdatedDate"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			SupplierCity    sql.NullString
			NormalizedCity  sql.NullString
			Region          sql.NullString
			LastUpdatedBy   sql.NullString
			LastUpdatedDate sql.NullString
		)
		if err := rows.Scan(&SupplierCity, &NormalizedCity, &Region, &LastUpdatedBy, &LastUpdatedDate); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on villesAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			SupplierCity:    SupplierCity.String,
			NormalizedCity:  NormalizedCity.String,
			Region:          Region.String,
			LastUpdatedBy:   LastUpdatedBy.String,
			LastUpdatedDate: LastUpdatedDate.String,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on villesAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func rampeAllHandler(w http.ResponseWriter, r *http.Request) {

	// à cause du fonctionnement d'une Float64, ceci cause une perte de précision lors de la transformation du prix ULSDQC1 en dollars
	// (EX: 176.1 = 176.1000001)
	//Pour réglé cette situation j'ai ajouter 3 colones qui ont Computer sur la valeur de ULSDQC1 / 100, stocker en decimal(10,4)
	//et celle-cis sont envoyer en JSON en tant que string.

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
	SELECT 
	[Date], PrixULSDQC1, GrosReservoir, PetitReservoir from dbo.valeroRackPrice
	order by [date] desc;
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on rampeAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date           string `json:"Date"`
		PrixULSDQC1    string `json:"ULSDQC1"`
		GrosReservoir  string `json:"GrosReservoir"`
		PetitReservoir string `json:"PetitReservoir"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date           sql.NullTime
			PrixULSDQC1    sql.NullString
			GrosReservoir  sql.NullString
			PetitReservoir sql.NullString
		)
		if err := rows.Scan(&Date, &PrixULSDQC1, &GrosReservoir, &PetitReservoir); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on rampeAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:           Date.Time.Format("2006-01-02"),
			PrixULSDQC1:    (PrixULSDQC1.String),
			GrosReservoir:  (GrosReservoir.String),
			PetitReservoir: (PetitReservoir.String),
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on rampeAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func peagesAllHandler(w http.ResponseWriter, r *http.Request) { // TO DO ONCE VIEW IS DONE
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
	SELECT 
	
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on peagesAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date    string  `json:"Date"`
		ULSDQC1 float32 `json:"ULSDQC1"`
		ULSD1   float32 `json:"ULSD1"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date    sql.NullTime
			ULSDQC1 sql.NullFloat64
			ULSD1   sql.NullFloat64
		)
		if err := rows.Scan(&Date, &ULSDQC1, &ULSD1); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on peagesAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:    Date.Time.Format("2006-01-02"),
			ULSDQC1: float32(ULSDQC1.Float64) / 100,
			ULSD1:   float32(ULSD1.Float64) / 100,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on peagesAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func camionsBrokerAllHandler(w http.ResponseWriter, r *http.Request) { // TO DO ONCE VIEW IS DONE
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Test query - get column info first
	query := `
	SELECT 
	
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), 500)
		logger.Info("Query error on camionsBrokerAllHandler: " + err.Error())
		return
	}
	defer rows.Close()

	type rowOut struct {
		Date    string  `json:"Date"`
		ULSDQC1 float32 `json:"ULSDQC1"`
		ULSD1   float32 `json:"ULSD1"`
	}
	out := make([]rowOut, 0, 256)

	for rows.Next() {
		var (
			Date    sql.NullTime
			ULSDQC1 sql.NullFloat64
			ULSD1   sql.NullFloat64
		)
		if err := rows.Scan(&Date, &ULSDQC1, &ULSD1); err != nil {
			http.Error(w, "scan error: "+err.Error(), 500)
			logger.Info("Scan error on camionsBrokerAllHandler: " + err.Error())
			return
		}

		out = append(out, rowOut{
			Date:    Date.Time.Format("2006-01-02"),
			ULSDQC1: float32(ULSDQC1.Float64) / 100,
			ULSD1:   float32(ULSD1.Float64) / 100,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "rows error: "+err.Error(), 500)
		logger.Info("Rows error on camionsBrokerAllHandler: " + err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// POSTs update and manipulate data
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on cartesAddHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
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
		respondWithError(w, http.StatusInternalServerError, ("database error: " + err.Error()))
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Resolve driverName -> Drivers.id using FirstName + ' ' + LastName (or just FirstName for petit vehicule drivers)
	var driverId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM dbo.Drivers 
		WHERE LTRIM(RTRIM(FirstName + ' ' + ISNULL(LastName, ''))) = @name
		   OR FirstName = @name
	`, sql.Named("name", strings.TrimSpace(body.DriverName))).Scan(&driverId); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "driver not found")
			return
		}
		logger.Info("QueryRow error on cartesAddHandler (resolve driver): " + err.Error())
		respondWithError(w, http.StatusInternalServerError, ("database error: " + err.Error()))
		return
	}

	// Resolve oil co if provided
	var oilCoIdParam interface{}
	if body.OilCoName != nil {
		oc := strings.TrimSpace(*body.OilCoName)
		if oc != "" {
			var oilCoId sql.NullInt64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM dbo.OilCo WHERE OilCoName = @name`, sql.Named("name", oc)).Scan(&oilCoId); err != nil {
				if err == sql.ErrNoRows {
					respondWithError(w, http.StatusBadRequest, "oil company not found")
					return
				}
				logger.Info("QueryRow error on cartesAddHandler (resolve oilco): " + err.Error())
				respondWithError(w, http.StatusInternalServerError, ("database error: " + err.Error()))
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
INSERT INTO dbo.Cartes (FK_DriverId, CardNumber, NIP, FK_OilCoId, Expiration, DateRemise, DateReprise, Notes)
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
		respondWithError(w, http.StatusInternalServerError, ("database error: " + err.Error()))
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesAddHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, ("database error: " + err.Error()))
		return
	}

	idVal := 0
	if newId.Valid {
		idVal = int(newId.Int64)
	}

	logger.Info(fmt.Sprintf("User %s added Card CardId=%d CardNumber=%s OperatorNo=%d", user, idVal, body.CardNumber, driverId.Int64))

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "CardId": idVal})
}
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Update assumed table dbo.Cards (adjust if necessary)
	updateQ := `
UPDATE dbo.Cartes
SET NIP = @nip,
	DateRemise = TRY_CONVERT(date, @dr, 120),
	DateReprise = TRY_CONVERT(date, @dre, 120),
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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
func cartesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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
FROM dbo.listCartes
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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
	delQ := `DELETE FROM dbo.Cartes WHERE CardId = @cid AND CardNumber = @cn;`
	if res, err := tx.ExecContext(ctx, delQ, sql.Named("cid", body.CardId), sql.Named("cn", body.CardNumber)); err != nil {
		logger.Info("Exec error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	} else {
		if ra, _ := res.RowsAffected(); ra == 0 {
			respondWithError(w, http.StatusBadRequest, "no rows deleted")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on cartesDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	logger.Info(fmt.Sprintf("User %s deleted CardId=%d CardNumber=%s", user, body.CardId, body.CardNumber))

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
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
		DeletedDate   string `json:"deletedDate"`
		CSRF          string `json:"csrf,omitempty"`
	}
	var body reqBody

	// Read raw body for diagnostics
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	logger.Info("brokersAddDriver raw body: " + string(b))
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on brokersAddDriver: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	session := GetSessionInfo(r)
	user := "unknown"
	if session != nil {
		user = session.Username
	}
	logger.Info(fmt.Sprintf("Utilisateur %s ajoute le chauffeur Broker: brokerId=%d brokerName=%q dispatchGroup=%d startDate=%q deletedDate=%s", user, body.BrokerId, body.BrokerName, body.DispatchGroup, body.StartDate, body.DeletedDate))

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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Verify broker exists
	var existingName sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT Nom_Commun FROM dbo.BrokerCo WHERE id = @id`, sql.Named("id", body.BrokerId)).Scan(&existingName); err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "broker not found")
			return
		}
		logger.Info("Query error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	// Determine next LastName (numeric suffix)
	var maxSuffix sql.NullInt64
	// Use TRY_CAST to safely convert LastName to int; unsupported DB will return NULL and ISNULL will give 0
	if err := tx.QueryRowContext(ctx, `
		SELECT ISNULL(MAX(TRY_CAST(LastName AS INT)), 0) FROM dbo.Drivers WHERE FirstName = @fname
	`, sql.Named("fname", body.BrokerName)).Scan(&maxSuffix); err != nil {
		logger.Info("Query error on brokersAddDriver (max suffix): " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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
	INSERT INTO dbo.Drivers (operatorNo, FirstName, LastName, FK_DispatchGroup, startDate, deletedDate, isBroker, FK_BrokerId)
	OUTPUT INSERTED.id
	VALUES (@operatorNo, @FirstName, @LastName, @FK_DispatchGroup, @startDate, @deletedDate, @isBroker, @FK_BrokerId);
	`
	var newId sql.NullInt64
	if err := tx.QueryRowContext(ctx, insertQ,
		sql.Named("operatorNo", operatorNo),
		sql.Named("FirstName", body.BrokerName),
		sql.Named("LastName", lastName),
		sql.Named("FK_DispatchGroup", body.DispatchGroup),
		sql.Named("startDate", body.StartDate),
		sql.Named("deletedDate", body.DeletedDate),
		sql.Named("isBroker", 1),
		sql.Named("FK_BrokerId", body.BrokerId),
	).Scan(&newId); err != nil {
		logger.Info("Insert error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	logger.Info(fmt.Sprintf("brokersAddDriver inserted id (tx): %v", newId))

	// Verify insertion
	var verifyId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT TOP 1 id FROM dbo.Drivers WHERE operatorNo = @op AND FK_BrokerId = @bid ORDER BY id DESC`, sql.Named("op", operatorNo), sql.Named("bid", body.BrokerId)).Scan(&verifyId); err != nil {
		if err == sql.ErrNoRows {
			logger.Info("Verification select: no rows found after insert for operatorNo=" + operatorNo)
		} else {
			logger.Info("Verification select error on brokersAddDriver: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
			return
		}
	} else {
		logger.Info(fmt.Sprintf("Verification select found id: %v", verifyId))
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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

// Update driver's dispatch group by operatorNo
func driversUpdateGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on driversUpdateGroupHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	type reqBody struct {
		OperatorNo    string `json:"operatorNo"`
		DispatchGroup int    `json:"dispatchGroup"`
		CSRF          string `json:"csrf,omitempty"`
	}
	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on driversUpdateGroupHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// CSRF
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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
		logger.Info("Invalid CSRF token provided to driversUpdateGroupHandler")
		return
	}

	if strings.TrimSpace(body.OperatorNo) == "" || body.DispatchGroup <= 0 {
		respondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on driversUpdateGroupHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Update by operatorNo
	updateQ := `UPDATE dbo.Drivers SET FK_DispatchGroup = @dg WHERE operatorNo = @op;`
	if _, err := tx.ExecContext(ctx, updateQ, sql.Named("dg", body.DispatchGroup), sql.Named("op", strings.TrimSpace(body.OperatorNo))); err != nil {
		logger.Info("Exec error on driversUpdateGroupHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on driversUpdateGroupHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	logger.Info(fmt.Sprintf("Updated driver dispatch group: operatorNo=%s dispatchGroup=%d", body.OperatorNo, body.DispatchGroup))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	logger.Info("brokersAddCo raw body: " + string(b))
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on brokersAddCo: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Insert driver and return new ID using OUTPUT
	insertQ := `
	SET NOCOUNT ON;
	INSERT INTO dbo.BrokerCo (Nom_Legal, Nom_Commun, Acomba)
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
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	logger.Info(fmt.Sprintf("brokersAddCo inserted id (tx): %v", newId))

	// Verify insertion
	var verifyId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT TOP 1 id FROM dbo.BrokerCo WHERE Nom_Legal = @nl and Nom_Commun = @nc and Acomba = @A`, sql.Named("nl", body.BrokerCoLegalName), sql.Named("nc", body.BrokerCoCommonName), sql.Named("A", body.BrokerCoAcomba)).Scan(&verifyId); err != nil {
		if err == sql.ErrNoRows {
			logger.Info("Verification select: no rows found after insert for Nom_Commun" + body.BrokerCoCommonName)
		} else {
			logger.Info("Verification select error on brokersAddCo: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
			return
		}
	} else {
		logger.Info(fmt.Sprintf("Verification select found id: %v", verifyId))
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on brokersAddDriver: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
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
func usersCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"isAdmin"`
		IsSuperUser bool   `json:"isSuperUser"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	password := strings.TrimSpace(body.Password)

	if username == "" || password == "" {
		respondWithError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	// Hash password with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Info("Bcrypt error on usersCreateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	insertQ := `INSERT INTO dbo.AppUser (AppUser, password_hash, IsAdmin, IsSuperUser) VALUES (@username, @hash, @isAdmin, @isSuperUser)`

	if _, err := db.ExecContext(ctx, insertQ,
		sql.Named("username", username),
		sql.Named("hash", string(hash)),
		sql.Named("isAdmin", body.IsAdmin),
		sql.Named("isSuperUser", body.IsSuperUser),
	); err != nil {
		logger.Info("Insert error on usersCreateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("User %s created by %s", username, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
func usersDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		ID int `json:"id"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.ID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Prevent deleting current user
	var targetUsername string
	err = db.QueryRowContext(ctx, "SELECT AppUser FROM dbo.AppUser WHERE id = @id", sql.Named("id", body.ID)).Scan(&targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersDeleteHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	if strings.EqualFold(targetUsername, session.Username) {
		respondWithError(w, http.StatusForbidden, "Cannot disable your own user account")
		return
	}

	// Prevent deleting last admin user
	var adminCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dbo.AppUser WHERE IsAdmin = 1").Scan(&adminCount)
	if err != nil {
		logger.Info("Count error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	var targetIsAdmin bool
	err = db.QueryRowContext(ctx, "SELECT IsAdmin FROM dbo.AppUser WHERE id = @id", sql.Named("id", body.ID)).Scan(&targetIsAdmin)
	if err != nil {
		logger.Info("Admin check error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if targetIsAdmin && adminCount <= 1 {
		respondWithError(w, http.StatusForbidden, "Cannot disable the last admin user")
		return
	}

	deleteQ := `update dbo.AppUser
	set IsDisabled = 1 
	WHERE id = @id`

	result, err := db.ExecContext(ctx, deleteQ, sql.Named("id", body.ID))
	if err != nil {
		logger.Info("Delete error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Info("RowsAffected error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if rowsAffected == 0 {
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	logger.Info(fmt.Sprintf("User ID %d disabled by %s", body.ID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
func usersChangePasswordForUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		UserID      int    `json:"userId"`
		NewPassword string `json:"newPassword"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.UserID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	newPassword := strings.TrimSpace(body.NewPassword)
	if newPassword == "" {
		respondWithError(w, http.StatusBadRequest, "New password is required")
		return
	}

	// Prevent admin from changing their own password via this endpoint
	var targetUsername string
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = db.QueryRowContext(ctx, "SELECT AppUser FROM dbo.AppUser WHERE id = @id", sql.Named("id", body.UserID)).Scan(&targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersChangePasswordForUserHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	if strings.EqualFold(targetUsername, session.Username) {
		respondWithError(w, http.StatusForbidden, "Use the regular change password endpoint for your own password")
		return
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Info("Bcrypt error on usersChangePasswordForUserHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}

	// Update password
	updateQ := `UPDATE dbo.AppUser SET password_hash = @hash WHERE id = @id`
	if _, err := db.ExecContext(ctx, updateQ,
		sql.Named("hash", string(newHash)),
		sql.Named("id", body.UserID),
	); err != nil {
		logger.Info("Update error on usersChangePasswordForUserHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("Password changed for user ID %d by %s", body.UserID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
func usersUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		UserID      int    `json:"userId"`
		NewPassword string `json:"newPassword"`
		IsAdmin     bool   `json:"isAdmin"`
		IsSuperUser bool   `json:"isSuperUser"`
		IsDisabled  bool   `json:"isDisabled"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.UserID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get target user info
	var targetUsername string
	var targetIsAdmin bool
	err = db.QueryRowContext(ctx, "SELECT AppUser, IsAdmin FROM dbo.AppUser WHERE id = @id", sql.Named("id", body.UserID)).Scan(&targetUsername, &targetIsAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	// Check if trying to remove admin status from last admin
	if targetIsAdmin && !body.IsAdmin {
		var adminCount int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dbo.AppUser WHERE IsAdmin = 1").Scan(&adminCount)
		if err != nil {
			logger.Info("Count error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
			return
		}

		if adminCount <= 1 {
			respondWithError(w, http.StatusForbidden, "Cannot remove admin status from the last admin user")
			return
		}
	}

	// Build update query
	var updateQ string
	var args []interface{}

	if strings.TrimSpace(body.NewPassword) != "" {
		// Hash new password
		newHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Info("Bcrypt error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Password hashing error")
			return
		}

		updateQ = `UPDATE dbo.AppUser SET password_hash = @hash, IsAdmin = @isAdmin, IsSuperUser = @isSuperUser, IsDisabled = @isDisabled WHERE id = @id`
		args = append(args,
			sql.Named("hash", string(newHash)),
			sql.Named("isAdmin", body.IsAdmin),
			sql.Named("isSuperUser", body.IsSuperUser),
			sql.Named("id", body.UserID),
			sql.Named("isDisabled", body.IsDisabled),
		)
	} else {
		updateQ = `UPDATE dbo.AppUser SET IsAdmin = @isAdmin, IsSuperUser = @isSuperUser, IsDisabled = @isDisabled WHERE id = @id`
		args = append(args,
			sql.Named("isAdmin", body.IsAdmin),
			sql.Named("isSuperUser", body.IsSuperUser),
			sql.Named("id", body.UserID),
			sql.Named("isDisabled", body.IsDisabled),
		)
	}

	if _, err := db.ExecContext(ctx, updateQ, args...); err != nil {
		logger.Info("Update error on usersUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("User ID %d updated by %s", body.UserID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
func villesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) && !IsSuperUser(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		SupplierCity   string `json:"SupplierCity"`
		NormalizedCity string `json:"NormalizedCity"`
		Region         string `json:"Region"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	SupplierCity := strings.TrimSpace(body.SupplierCity)
	NormalizedCity := strings.ToLower(strings.TrimSpace(body.NormalizedCity))
	Region := strings.ToLower(strings.TrimSpace(body.Region))
	LastUpdateBy := session.Username
	LastUpdateDate := time.Now().Local()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	updateQ := `UPDATE dbo.CityNormalization 
	SET 
	NormalizedCity = @NormalizedCity,
	Region = @Region,
	LastUpdatedBy = @LastUpdatedBy,
	LastUpdatedDate = @LastUpdatedDate
	where SupplierCity = @SupplierCity
	`

	if _, err := db.ExecContext(ctx, updateQ,
		sql.Named("SupplierCity", SupplierCity),
		sql.Named("NormalizedCity", NormalizedCity),
		sql.Named("Region", Region),
		sql.Named("LastUpdatedBy", LastUpdateBy),
		sql.Named("LastUpdatedDate", LastUpdateDate),
	); err != nil {
		logger.Info("Insert error on villesUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("User: %s updated Ville %s to Normalized %s", LastUpdateBy, SupplierCity, NormalizedCity))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// petrolieresAddOilCoHandler - Add a new OilCo (Pétrolière)
func petrolieresAddOilCoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !IsAdmin(r) && !IsSuperUser(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Parse request JSON
	type reqBody struct {
		OilCoName string `json:"OilCoName"`
		Compte    string `json:"Compte"`
		Banner    string `json:"Banner"`
		CSRF      string `json:"csrf,omitempty"`
	}
	var body reqBody

	// Read raw body for diagnostics
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Info("ReadAll error on petrolieresAddOilCoHandler: " + err.Error())
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	logger.Info("petrolieresAddOilCoHandler raw body: " + string(b))
	if err := json.Unmarshal(b, &body); err != nil {
		logger.Info("JSON unmarshal error on petrolieresAddOilCoHandler: " + err.Error() + " -- raw: " + string(b))
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	session := GetSessionInfo(r)
	user := "unknown"
	if session != nil {
		user = session.Username
	}
	logger.Info(fmt.Sprintf("Utilisateur %s ajoute une pétrolière: OilCoName=%s, Compte=%s, Banner=%s", user, body.OilCoName, body.Compte, body.Banner))

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
		logger.Info("Invalid CSRF token provided to petrolieresAddOilCoHandler")
		respondWithError(w, http.StatusForbidden, "Token Invalid, Recharger la page")
		return
	}

	// Generate and set a fresh token for subsequent requests
	if newToken, err := csrfManager.GenerateToken(); err == nil {
		csrfManager.SetTokenCookie(w, newToken)
	} else {
		logger.Info("Failed to generate CSRF token after petrolieresAddOilCoHandler: " + err.Error())
	}

	if strings.TrimSpace(body.OilCoName) == "" {
		respondWithError(w, http.StatusBadRequest, "OilCoName required")
		return
	}

	// Start transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.Info("BeginTx error on petrolieresAddOilCoHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Insert OilCo and return new ID using OUTPUT
	insertQ := `
	SET NOCOUNT ON;
	INSERT INTO dbo.OilCo (OilCoName, Compte, Banner)
	OUTPUT INSERTED.id
	VALUES (@OilCoName, @Compte, @Banner);
	`
	var newId sql.NullInt64
	if err := tx.QueryRowContext(ctx, insertQ,
		sql.Named("OilCoName", body.OilCoName),
		sql.Named("Compte", body.Compte),
		sql.Named("Banner", body.Banner),
	).Scan(&newId); err != nil {
		logger.Info("Insert error on petrolieresAddOilCoHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	logger.Info(fmt.Sprintf("petrolieresAddOilCoHandler inserted id (tx): %v", newId))

	// Verify insertion
	var verifyId sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT TOP 1 id FROM dbo.OilCo WHERE OilCoName = @OilCoName ORDER BY id DESC`, sql.Named("OilCoName", body.OilCoName)).Scan(&verifyId); err != nil {
		if err == sql.ErrNoRows {
			logger.Info("Verification select: no rows found after insert for OilCoName=" + body.OilCoName)
		} else {
			logger.Info("Verification select error on petrolieresAddOilCoHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
			return
		}
	} else {
		logger.Info(fmt.Sprintf("Verification select found id: %v", verifyId))
	}

	if err := tx.Commit(); err != nil {
		logger.Info("Commit error on petrolieresAddOilCoHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "database error: "+err.Error())
		return
	}

	res := map[string]interface{}{
		"id":        nil,
		"OilCoName": body.OilCoName,
		"Compte":    body.Compte,
		"Banner":    body.Banner,
	}
	if newId.Valid {
		res["id"] = int(newId.Int64)
	}

	respondWithJSON(w, http.StatusOK, res)
}
