using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SSP.Data;
using SSP.Models.Domain;
using SSP.Models.ViewModels;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace SSP.Controllers
{
    public class AccountController : Controller
    {
        private readonly StudyPortalDbContext _context;
        private readonly PasswordHasher<Student> _passwordHasherStudent;
        private readonly PasswordHasher<Admin> _passwordHasherAdmin;

        public AccountController(StudyPortalDbContext context)
        {
            _context = context;
            _passwordHasherStudent = new PasswordHasher<Student>();
            _passwordHasherAdmin = new PasswordHasher<Admin>();
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (_context.Students.Any(s => s.S_Email == model.S_Email))
                {
                    ModelState.AddModelError("S_Email", "This email is already registered.");
                    return View(model);
                }

                var student = new Student
                {
                    S_Id = Guid.NewGuid(),
                    S_Name = model.S_Name,
                    S_Email = model.S_Email,
                    S_Password = _passwordHasherStudent.HashPassword(null, model.S_Password)
                };

                _context.Students.Add(student);
                _context.SaveChanges();
                return RedirectToAction("Login");
            }
            return View(model);
        }

        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.IsInRole("Admin"))
                    return RedirectToAction("AdminDashboard", "Admin");

                if (User.IsInRole("Student"))
                    return RedirectToAction("StudentDashboard", "Student"); // ✅ Redirect to StudentDashboard
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            // 🔍 Check for Admin
            var admin = _context.Admins.FirstOrDefault(a => a.A_Email == model.Email);
            if (admin != null)
            {
                var result = _passwordHasherAdmin.VerifyHashedPassword(admin, admin.A_Password, model.Password);
                if (result == PasswordVerificationResult.Success)
                {
                    var logEntry = new AuditLog
                    {
                        UserEmail = model.Email,
                        Action = "Admin Logged In",
                        Timestamp = DateTime.Now,
                        LogoutTime = null
                    };
                    _context.AuditLogs.Add(logEntry);
                    _context.SaveChanges();
                    HttpContext.Session.SetInt32("AuditLogId", logEntry.Id);

                    var claims = new List<System.Security.Claims.Claim>
                    {
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, admin.A_Name),
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, admin.A_Email),
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "Admin")
                    };

                    var identity = new System.Security.Claims.ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    return RedirectToAction("AdminDashboard", "Admin");
                }
            }

            // 🔍 Check for Student
            var student = _context.Students.FirstOrDefault(s => s.S_Email == model.Email);
            if (student != null)
            {
                var result = _passwordHasherStudent.VerifyHashedPassword(student, student.S_Password, model.Password);
                if (result == PasswordVerificationResult.Success)
                {
                    HttpContext.Session.SetString("StudentName", student.S_Name);

                    var logEntry = new AuditLog
                    {
                        UserEmail = model.Email,
                        Action = "Student Logged In",
                        Timestamp = DateTime.Now,
                        LogoutTime = null
                    };

                    _context.AuditLogs.Add(logEntry);
                    _context.SaveChanges();
                    HttpContext.Session.SetInt32("AuditLogId", logEntry.Id);

                    var claims = new List<System.Security.Claims.Claim>
                    {
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, student.S_Name),
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, student.S_Email),
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "Student")
                    };

                    var identity = new System.Security.Claims.ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                    return RedirectToAction("StudentDashboard", "Student"); // ✅ Final Redirect
                }
            }

            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            var auditLogId = HttpContext.Session.GetInt32("AuditLogId");
            if (auditLogId != null)
            {
                var auditLog = _context.AuditLogs.FirstOrDefault(a => a.Id == auditLogId);
                if (auditLog != null)
                {
                    auditLog.LogoutTime = DateTime.Now;
                    _context.SaveChanges();
                }
            }

            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("Index", "Home"); // Redirect to homepage
        }
    }
}
