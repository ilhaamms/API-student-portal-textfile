package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_role")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if c.Value != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
			return
		}

		next.ServeHTTP(w, r)
	}) // TODO: replace this
}

func Login(w http.ResponseWriter, r *http.Request) {

	var credential model.UserLogin

	err := json.NewDecoder(r.Body).Decode(&credential)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	if credential.ID == "" || credential.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID or Name is empty"})
		return
	}

	userData, err := GetUserData()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	for _, user := range userData {
		if user.ID == credential.ID && user.Name == credential.Name {
			cookie := http.Cookie{
				Name:  "user_login_id",
				Value: user.ID,
			}
			http.SetCookie(w, &cookie)
			cookie = http.Cookie{
				Name:  "user_login_role",
				Value: user.Role,
			}
			http.SetCookie(w, &cookie)

			UserLogin[user.ID] = user

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(model.SuccessResponse{Username: credential.Name, Message: "login success"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user not found"})

}

func GetStudyCode() ([]model.StudyData, error) {

	file, err := os.Open(filepath.Join("data", "list-study.txt"))
	if err != nil {
		return nil, fmt.Errorf("internal server error : %w", err)
	}

	defer file.Close()

	listStudy := []model.StudyData{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := scanner.Text()
		split := strings.Split(line, "_")
		listStudy = append(listStudy, model.StudyData{
			Code: split[0],
			Name: split[1],
		})
	}

	return listStudy, nil
}

func GetUserData() ([]model.User, error) {
	_, err := os.Stat(filepath.Join("data", "users.txt"))
	if os.IsNotExist(err) {
		f, err := os.Create(filepath.Join("data", "users.txt"))
		if err != nil {
			return nil, fmt.Errorf("internal server error : %w", err)
		}
		f.Close()
		return []model.User{}, nil
	}

	f, err := os.Open(filepath.Join("data", "users.txt"))
	if err != nil {
		return nil, fmt.Errorf("internal server error : %w", err)
	}

	defer f.Close()

	var listUser []model.User

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, "_")
		listUser = append(listUser, model.User{
			ID:        split[0],
			Name:      split[1],
			StudyCode: split[2],
			Role:      split[3],
		})
	}

	return listUser, nil
}

func checkUserIDAndStudy(user model.User) error {

	listStudy, err := GetStudyCode()
	if err != nil {
		return err
	}

	isStudyExist := false
	for _, dataStudy := range listStudy {

		if user.StudyCode == dataStudy.Code {
			isStudyExist = true
			break
		}
	}

	if !isStudyExist {
		return errors.New("study code not found")
	}

	listUser, err := GetUserData()
	if err != nil {
		return err
	}

	isIdExist := false
	for _, dataUser := range listUser {

		if user.ID == dataUser.ID {
			isIdExist = true
			break
		}
	}

	if isIdExist {
		return errors.New("user id already exist")
	}

	return nil
}

func Register(w http.ResponseWriter, r *http.Request) {

	var user model.User
	json.NewDecoder(r.Body).Decode(&user)

	if user.ID == "" || user.Name == "" || user.Role == "" || user.StudyCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: "ID, name, study code or role is empty",
		})
		return
	}

	err := checkUserIDAndStudy(user)
	if err != nil {
		if strings.Contains(err.Error(), "internal server error") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(model.ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	if user.Role != "admin" && user.Role != "user" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: "role must be admin or user",
		})
		return
	}

	userData, _ := GetUserData()
	newUserData := append(userData, user)
	_ = saveUserData(newUserData)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: user.ID,
		Message:  "register success",
	})
}

func saveUserData(data []model.User) error {

	f, err := os.Create(filepath.Join("data", "users.txt"))
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	var writeData string

	for _, user := range data {
		writeData += fmt.Sprintf("%s_%s_%s_%s\n", user.ID, user.Name, user.StudyCode, user.Role)
	}

	_, err = f.WriteString(writeData)
	if err != nil {
		return err
	}

	return nil

}

func Logout(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)

	delete(UserLogin, userID)

	cookie := http.Cookie{
		Name:  "user_login_id",
		Value: "",
	}
	http.SetCookie(w, &cookie)
	cookie = http.Cookie{
		Name:  "user_login_role",
		Value: "",
	}
	http.SetCookie(w, &cookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: userID,
		Message:  "logout success",
	})

	// TODO: answer here
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {
	// list study program
	listStudy, err := GetStudyCode()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(listStudy)
}

func AddUser(w http.ResponseWriter, r *http.Request) {

	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
		return
	}

	if user.ID == "" || user.Name == "" || user.StudyCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, study code or role is empty"})
		return
	}

	user.Role = "user"

	err = checkUserIDAndStudy(user)
	if err != nil {
		if strings.Contains(err.Error(), "internal server error") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(model.ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	userData, err := GetUserData()
	userData = append(userData, user)

	_ = saveUserData(userData)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{Username: user.ID, Message: "add user success"})

}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	userData, err := GetUserData()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	userId := r.URL.Query().Get("id")

	if userId == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: "user id is empty",
		})
		return
	}

	var newUserData []model.User
	found := false
	for _, user := range userData {
		if user.ID != userId {
			newUserData = append(newUserData, user)
		} else {
			found = true
		}
	}

	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{
			Error: "user id not found",
		})
		return
	}

	_ = saveUserData(newUserData)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: userId,
		Message:  "delete success",
	})
}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/get-weather" {
		http.Error(w, "Invalid request", http.StatusMethodNotAllowed)
		return
	}

	var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}
	var wg sync.WaitGroup
	var mu sync.Mutex

	var resCh = make(chan model.MainWeather, len(listRegion))
	var errorsCh = make(chan error, len(listRegion))

	for _, region := range listRegion {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			weather, err := client.GetWeatherByRegion(region)
			if err != nil {
				errorsCh <- err
				return
			}
			mu.Lock()
			resCh <- weather
			mu.Unlock()
		}(region)
	}

	go func() {
		wg.Wait()
		close(resCh)
		close(errorsCh)
	}()

	var weatherData []model.MainWeather
	var errors []error

	for weather := range resCh {
		weatherData = append(weatherData, weather)
	}

	for err := range errorsCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	responseData, err := json.Marshal(weatherData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseData)
}
