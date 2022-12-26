package v1

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nurmuhammaddeveloper/medium_api_gateway/api/models"
	pbu "github.com/nurmuhammaddeveloper/medium_api_gateway/genproto/user_service"
	"google.golang.org/grpc/status"
)

// @Router /auth/register [post]
// @Summary Register a user
// @Description Register a user
// @Tags login
// @Accept json
// @Produce json
// @Param data body models.RegisterRequest true "Data"
// @Success 200 {object} models.ResponseOK
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) Register(c *gin.Context) {
	var (
		req models.RegisterRequest
	)

	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	user, _ := h.grpcClient.UserService().GetByEmail(context.Background(), &pbu.GetByEmailRequest{
		Email: req.Email,
	})
	if user != nil {
		c.JSON(http.StatusBadRequest, errorResponse(ErrEmailExists))
		return
	}

	_, err = h.grpcClient.AuthService().Register(context.Background(), &pbu.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	c.JSON(http.StatusOK, models.ResponseOK{
		Message: "success",
	})
}

// @Router /auth/verify [post]
// @Summary Verify user
// @Description Verify user
// @Tags login
// @Accept json
// @Produce json
// @Param data body models.VerifyRequest true "Data"
// @Success 200 {object} models.AuthResponse
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) Verify(ctx *gin.Context) {
	var (
		req models.VerifyRequest
	)
	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	res, err := h.grpcClient.AuthService().Verify(context.Background(), &pbu.VerifyRequest{
		Email: req.Email,
		Code:  req.Code,
	})
	if err != nil {
		s, _ := status.FromError(err)
		if s.Message() == "incorrect_code" {
			ctx.JSON(http.StatusBadRequest, errorResponse(err))
			return
		} else if s.Message() == "code_expired" {
			ctx.JSON(http.StatusBadRequest, errorResponse(ErrCodeExpired))
			return
		} else {
			ctx.JSON(http.StatusInternalServerError, errorResponse(err))
			return
		}
	}
	ctx.JSON(http.StatusCreated, models.AuthResponse{
		ID:          res.Id,
		FirstName:   res.FirstName,
		LastName:    res.LastName,
		Email:       res.Email,
		Type:        res.Type,
		CreatedAt:   res.CreatedAt,
		AccessToken: res.AccessToken,
	})
}

// @Router /auth/login [post]
// @Summary Login User
// @Description Login User
// @Tags login
// @Accept json
// @Produce json
// @Param login body models.LoginRequest true "Login"
// @Success 200 {object} models.AuthResponse
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) Login(ctx *gin.Context) {
	var (
		req models.LoginRequest
	)
	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		h.logger.WithError(err).Error("filed to bind json in login")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	user, err := h.grpcClient.AuthService().Login(context.Background(), &pbu.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.logger.WithError(err).Error("filed to login")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	ctx.JSON(http.StatusOK, models.AuthResponse{
		ID:          user.Id,
		FirstName:   user.FirstName,
		LastName:    user.LastName,
		Email:       user.Email,
		Type:        user.Type,
		CreatedAt:   user.CreatedAt,
		AccessToken: user.AccessToken,
	})
}

// @Router /auth/forgot-password [post]
// @Summary Forgot  password
// @Description Forgot  password
// @Tags login
// @Accept json
// @Produce json
// @Param data body models.ForgotPasswordRequest true "Data"
// @Success 200 {object} models.ResponseSuccess
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) ForgotPassword(ctx *gin.Context) {
	var (
		req models.ForgotPasswordRequest
	)
	if err := ctx.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("Filed to binding JSON in forgit password")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	_, err := h.grpcClient.AuthService().ForgotPassword(context.Background(), &pbu.ForgotPasswordRequest{
		Email: req.Email,
	})
	if err != nil {
		if err != nil {
			h.logger.WithError(err).Error("failed in forgot password")
			ctx.JSON(http.StatusInternalServerError, errorResponse(err))
			return
		}
	}
	ctx.JSON(http.StatusCreated, models.ResponseSuccess{
		Success: "Validation code has been sent",
	})
}

// @Router /auth/verify-forgot-password [post]
// @Summary Verify forgot password
// @Description Verify forgot password
// @Tags login
// @Accept json
// @Produce json
// @Param data body models.VerifyRequest true "Data"
// @Success 200 {object} models.AuthResponse
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) VerifyForgotPassword(ctx *gin.Context) {
	var (
		req models.VerifyRequest
	)
	if err := ctx.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("failed to bind JSON in verifyforgotpassword")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	result, err := h.grpcClient.AuthService().VerifyForgotPassword(context.Background(), &pbu.VerifyRequest{
		Email: req.Email,
		Code:  req.Code,
	})
	if err != nil {
		h.logger.WithError(err).Error("failed in verifyforgotpassword")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	ctx.JSON(http.StatusCreated, models.AuthResponse{
		ID:          result.Id,
		FirstName:   result.FirstName,
		LastName:    result.LastName,
		Email:       result.Email,
		Type:        result.Type,
		CreatedAt:   result.CreatedAt,
		AccessToken: result.AccessToken,
	})
}

// @Security ApiKeyAuth
// @Router /auth/update-password [post]
// @Summary Update password
// @Description Update password
// @Tags login
// @Accept json
// @Produce json
// @Param data body models.UpdatePasswordRequest true "Data"
// @Success 200 {object} models.ResponseSuccess
// @Failure 500 {object} models.ErrorResponse
func (h *handlerV1) UpdatePassword(ctx *gin.Context) {
	var (
		req models.UpdatePasswordRequest
	)

	if err := ctx.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Error("failed to bind JSON in updatepassword")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	payload, err := h.GetAuthPayload(ctx)
	if err != nil {
		h.logger.WithError(err).Error("failed to get payload in update password")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	_, err = h.grpcClient.AuthService().UpdatePassword(context.Background(), &pbu.UpdatePasswordRequest{
		UserId:   payload.UserID,
		Password: req.Password,
	})
	if err != nil {
		h.logger.WithError(err).Error("failed to update password")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusCreated, models.ResponseSuccess{
		Success: "Password has been updated!",
	})
}