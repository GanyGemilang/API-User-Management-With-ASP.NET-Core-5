using api.usermanagement.Models;
using api.usermanagement.Repositories;
using api.usermanagement.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace api.usermanagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly UserRepository userRepository;
        private readonly LogicRepository logicRepository;
        private readonly MailRepository mailRepository;
        private readonly jwtToken jwttoken;
        private readonly PasswordRepository passwordRepository;
        public UserController(IConfiguration configuration, UserRepository userRepository, jwtToken jwttoken, LogicRepository logicRepository, PasswordRepository passwordRepository, MailRepository mailRepository)
        {
            this.configuration = configuration;
            this.userRepository = userRepository;
            this.jwttoken = jwttoken;
            this.logicRepository = logicRepository;
            this.passwordRepository = passwordRepository;
            this.mailRepository = mailRepository;
        }

        [HttpPost("Registrasi")]
        public async Task<IActionResult> Registrasi(modelInputUser user)
        {
            try
            {
                if (user.username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", user));
                }
                else if (user.password == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "password cannot be null", user));
                }

                //Cek Logic Register
                var logic = await logicRepository.LogicRegister(user);
                if (logic.Code != "200")
                {
                    return StatusCode(int.Parse(logic.Code), Utilities.Response.ResponseMessage(logic.Code, "False", logic.Hasil, null));
                }
                user.password = logic.Hasil;

                //Insert Data User
                var insertUser = await userRepository.InsertUser(user);
                if (insertUser < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Insert User Failed", user));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Insert User Successful", user));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }

        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(modelLogin login)
        {
            try
            {
                if (login.username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", login));
                }
                else if (login.password == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "password cannot be null", login));
                }

                //Cek Logic ChangePassword
                var logic = await logicRepository.LogicLogin(login);
                if (logic.Code != "200")
                {
                    return StatusCode(int.Parse(logic.Code), Utilities.Response.ResponseMessage(logic.Code, "False", logic.Hasil, null));
                }

                //Update ke tbl_user
                var updateLogin = await userRepository.Login(logic.Hasil);
                if (updateLogin < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Filed Update Login", login));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Login Successful", new { Token = logic.Token }));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPost("Logout")]
        public async Task<IActionResult> Logout(modelLogout logout)
        {
            try
            {
                if (logout.username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", logout));
                }

                var Logout = await userRepository.Logout(logout.username);
                if (Logout < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Filed Update Login", Logout));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Logout Successful", Logout));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPut("ChangePassword")]
        public async Task<IActionResult> ChangePassword(modelChangePassword model)
        {
            try
            {
                if (model.password == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "Password cannot be null", null));
                }
                else if (model.newpassword == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "newpassword cannot be null", null));
                }
                else if (model.confirmpassword == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "confirmpassword cannot be null", null));
                }

                //Get Username in JWT
                HttpContext.Request.Headers.TryGetValue("Authorization", out var authorizationToken);
                var token = authorizationToken.ToString().Replace("Bearer ", "");
                var jwtReader = new JwtSecurityTokenHandler();
                var jwt = jwtReader.ReadJwtToken(token);
                string Username = jwt.Claims.First(c => c.Type == "Username").Value;

                //Cek Logic ChangePassword
                var logic = await logicRepository.LogicChangePassword(Username, model);
                if (logic.Code != "200")
                {
                    return StatusCode(int.Parse(logic.Code), Utilities.Response.ResponseMessage(logic.Code, "False", logic.Hasil, null));
                }

                var result = await userRepository.ChangePassword(Username, logic.Hasil);
                if (result < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Filed Update Password", result));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Change Password Successful", result));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }
        
        [HttpPut("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(modelForgotPassword model)
        {
            try
            {
                if (model.email == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "Email cannot be null", null));
                }

                //Generate Password
                var password = passwordRepository.Generate(8);
                //Encrypt Password
                string passwordhash = BCrypt.Net.BCrypt.HashPassword(password);


                //Cek Logic ChangePassword
                var forgot = await userRepository.ForgotPassword(model.email, passwordhash);
                var Hasil = forgot.FirstOrDefault();
                if (Hasil.Code != "200")
                {
                    return StatusCode(int.Parse(Hasil.Code), Utilities.Response.ResponseMessage(Hasil.Code, "False", Hasil.Message, null));
                }
                else
                {
                    var time24 = DateTime.Now.ToString("HH:mm:ss");
                    MailRequest mail = new MailRequest();
                    mail.ToEmail = model.email;
                    mail.Subject = "Forgot Password User Management " + time24;
                    mail.Body = time24 + " Password has been changed. New Password Is " + password;

                    var sendEmail =  mailRepository.SendEmailAsync(mail);
                    return Ok(Utilities.Response.ResponseMessage("200", "True", Hasil.Message,new {Email = model.email, Password = password } ));
                }
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("GetUserByUsername")]
        public async Task<IActionResult> GetUserByUsername(string username)
        {
            try
            {
                if (username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", null));
                }

                var data = await userRepository.GetUserbyusername(username);
                if (data.Count < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Filed Update Login", null));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Get data User Successful", data.FirstOrDefault()));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("GetUser")]
        public async Task<IActionResult> GetUser()
        {
            try
            {
                var data = await userRepository.GetUser();
                if (data.Count < 1)
                {
                    return StatusCode(404, Utilities.Response.ResponseMessage("404", "False", "Filed Update Login", null));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Get data User Successful", data));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }
        
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpDelete("DeleteUser")]
        public async Task<IActionResult> DeleteUser(string username)
        {
            try
            {
                if (username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", username));
                }

                var data = await userRepository.DeleteUser(username);
                var Hasil = data.FirstOrDefault();
                if (Hasil.Code != "200")
                {
                    return StatusCode(int.Parse(Hasil.Code), Utilities.Response.ResponseMessage(Hasil.Code, "False", Hasil.Message, null));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", Hasil.Message, username));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPut("UpdateUser")]
        public async Task<IActionResult> UpdateUser(modelUpdateUser user)
        {
            try
            {
                if (user.username == null)
                {
                    return StatusCode(400, Utilities.Response.ResponseMessage("400", "False", "username cannot be null", user));
                }

                //Update Data User
                var updatetUser = await userRepository.UpdateUser(user);
                var update = updatetUser.FirstOrDefault();
                if (update.Code != "200")
                {
                    return StatusCode(int.Parse(update.Code), Utilities.Response.ResponseMessage(update.Code, "False", update.Message, user));
                }
                return Ok(Utilities.Response.ResponseMessage("200", "True", "Insert User Successful", user));
            }
            catch (Exception e)
            {
                return StatusCode(500, Utilities.Response.ResponseMessage("500", "False", e.Message, null));
            }
        }
    }
}
