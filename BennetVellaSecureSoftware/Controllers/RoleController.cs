using BennetVellaSecureSoftware.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace BennetVellaSecureSoftware.Controllers
{
    public class RoleController : Controller
    {
        private Entities db = new Entities();

        // GET: Roles
        [Authorize(Roles = "Admin")]
        public ActionResult Index()
        {
            return View(db.AspNetUsers.ToList());
        }

        // GET: Articles/Edit/5
        [Authorize(Roles = "Admin")]
        public ActionResult Remove(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            AspNetUser user = db.AspNetUsers.Find(id);

            if (user == null)
            {
                return HttpNotFound();
            }

            IEnumerable<AspNetRole> currentRoles = user.AspNetRoles;
            ViewBag.Id = new SelectList(currentRoles, "Id", "Name");
            TempData["UserId"] = id;

            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult Remove(AspNetRole role)
        {

            string tmpUserId = (string)TempData.Peek("UserId");
            AspNetUser user = db.AspNetUsers.Find(tmpUserId);

            if (ModelState.IsValid)
            {
                user.AspNetRoles.Remove(db.AspNetRoles.Find(role.Id));
                db.SaveChanges();
            }

            IEnumerable<AspNetRole> currentRoles = user.AspNetRoles;
            ViewBag.Id = new SelectList(currentRoles, "Id", "Name");

            ViewBag.Message = "Role removed from user: " + user.UserName;

            return View();
        }

        // GET: Articles/Edit/5
        [Authorize(Roles = "Admin")]
        public ActionResult Add(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            AspNetUser user = db.AspNetUsers.Find(id);

            if (user == null)
            {
                return HttpNotFound();
            }

            IEnumerable<AspNetRole> currentRoles = db.AspNetRoles.ToList().Except(db.AspNetUsers.SingleOrDefault(u => u.Id == id).AspNetRoles.ToList());
            ViewBag.Id = new SelectList(currentRoles, "Id", "Name");
            TempData["UserId"] = id;

            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult Add(AspNetRole role)
        {

            string tmpUserId = (string)TempData.Peek("UserId");
            AspNetUser user = db.AspNetUsers.Find(tmpUserId);

            if (ModelState.IsValid)
            {
                user.AspNetRoles.Add(db.AspNetRoles.Find(role.Id));
                db.SaveChanges();
            }

            IEnumerable<AspNetRole> currentRoles = db.AspNetRoles.ToList().Except(db.AspNetUsers.SingleOrDefault(u => u.Id == tmpUserId).AspNetRoles.ToList());
            ViewBag.Id = new SelectList(currentRoles, "Id", "Name");

            ViewBag.Message = "Role added to user: " + user.UserName;

            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}