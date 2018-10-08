using BennetVellaSecureSoftware.Models;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace BennetVellaSecureSoftware.Controllers
{
    public class ArticleController : Controller
    {
        Entities db = new Entities();

        #region Get Actions
        // GET: Articles
        [Authorize(Roles = "Author, Admin")]
        public ActionResult Index()
        {
            IEnumerable<Publish> toPublish = db.Publishes.ToList();

            foreach (Publish p in toPublish)
            {
                if (p.PublishDate <= DateTime.Today)
                {
                    p.Article.StateId = 4;
                    db.Publishes.Remove(p);
                }
            }

            db.SaveChanges();

            string userId = User.Identity.GetUserId();
            IEnumerable<Article> articles = db.Articles.Where(a => a.UserId == userId);
            return View(articles);
        }

        [Authorize(Roles = "Author, Admin")] // Author Review
        public ActionResult PendingReview()
        {
            IEnumerable<Article> articles = db.Articles.Where(a => a.ArticleState.Name == "Pending");
            return View(articles);
        }

        [Authorize(Roles = "MediaManager, Admin")] // MediaManager Review
        public ActionResult PendingEditorial()
        {
            IEnumerable<Article> articles = db.Articles.Where(a => a.ArticleState.Name == "Reviewed");
            return View(articles);
        }

        // GET: Articles/Create
        [Authorize(Roles = "Author, Admin")]
        public ActionResult Create()
        {
            return View();
        }

        // GET: Articles/Edit/5
        [Authorize(Roles = "Author, Admin")]
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("BadRequest");
            }

            Article article = db.Articles.Find(id);

            if (article == null)
            {
                return RedirectToAction("Missing");
            }

            return View(article);
        }

        // GET: Articles/Details/5
        [Authorize]
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("BadRequest");
            }

            Article article = db.Articles.Find(id);

            if (article == null)
            {
                return RedirectToAction("Missing");
            }

            return View(article);
        }

        // GET: Articles/Details/5
        [Authorize(Roles = "Author, Admin")]
        public ActionResult Review(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("BadRequest");
            }
            Article article = db.Articles.Find(id);

            if (article == null)
            {
                return RedirectToAction("Missing");
            }

            var articleReview = new ArticleReview
            {
                articleModel = article,
                reviewModel = new Review()
            };
            return View(articleReview);
        }

        [Authorize(Roles = "Member")]
        public ActionResult Download(string fileName)
        {
            bool isPublished = false;
            if (db.Articles.SingleOrDefault(a => a.FileName == fileName).StateId == 4)
            {
                isPublished = true;
            }
            bool advancedUser = false;
            if (User.IsInRole("Author") || User.IsInRole("MediaManager"))
            {
                advancedUser = true;
            }


            if (advancedUser == false && isPublished == false)
            {
                return RedirectToAction("Missing");
            }
            else
            {
                try
                {
                    EncryptionUtility utility = new EncryptionUtility();

                    SymmetricParameters parameters = new SymmetricParameters();
                    string userId = db.Articles.SingleOrDefault(a => a.FileName == fileName).UserId;
                    // Public and private keys are generated during user registration, stored in UserKey table                  
                    string publicKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PublicKey;
                    string privateKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PrivateKey;
                    string signature = db.Articles.SingleOrDefault(a => a.FileName == fileName).Signature;

                    // Retrieval Process
                    string filePath = Server.MapPath(@"\Files" + @"\" + fileName);
                    string encryptedFile = utility.ReadFromFile(filePath);

                    // Decryption Process          
                    string[] splitString = encryptedFile.Split(new string[] { "#CONTENT#" }, StringSplitOptions.None);
                    string[] keyiv = splitString[0].Split(new string[] { "$KEY$" }, StringSplitOptions.None);
                    string SK = keyiv[0];
                    string IV = keyiv[1];
                    string encryptedContent = splitString[1];

                    parameters.SecretKey = utility.Decrypt(SK, privateKey);
                    parameters.IV = utility.Decrypt(IV, privateKey);

                    //Decrypt file using Secret key and IV
                    byte[] decryptedFile = utility.Decrypt(encryptedContent, parameters);

                    bool verify = utility.VerifySignature(decryptedFile, publicKey, signature);

                    ViewBag.isValid = verify.ToString();
                    return File(decryptedFile, System.Net.Mime.MediaTypeNames.Application.Octet, "Article");
                }
                catch
                {
                    return RedirectToAction("Missing");
                }
            }         
        }

        // GET: Articles/Review
        [Authorize(Roles = "MediaManager, Admin")]
        public ActionResult EditorialReview(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("BadRequest");
            }

            // Create article
            Article article = db.Articles.Find(id);
            Review review = db.Articles.Find(id).Review;

            if (article == null || review == null)
            {
                return RedirectToAction("Missing");
            }

            // Using the View Model created
            var articleReview = new ArticleReview
            {
                articleModel = article,
                reviewModel = review
            };

            TempData["tmpArticleReview"] = articleReview;

            return View(articleReview);
        }

        // GET: Articles/Delete/5
        [Authorize(Roles = "Admin")]
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("BadRequest");
            }
            Article article = db.Articles.Find(id);
            if (article == null)
            {
                return RedirectToAction("Missing");
            }
            return View(article);
        }
        #endregion

        #region Post Actions

        // POST: Articles/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [Authorize(Roles = "Author, Admin")]
        [ValidateAntiForgeryToken]
        [FileCheckActionFilter]
        public ActionResult Create([Bind(Include = "Id,Title")] Article article, HttpPostedFileBase file)
        {
            if (ModelState.IsValid)
            {
                try {
                    EncryptionUtility utility = new EncryptionUtility();
                    SymmetricParameters parameters = utility.GenerateSymmetricParameters("123qwe", "ijbygcrz");
                    string userId = User.Identity.GetUserId();
                    // Public and private keys are generated during user registration, stored in UserKey table                  
                    string publicKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PublicKey;
                    string privateKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PrivateKey;

                    //Convert file into an array of bytes, results saved in memory
                    MemoryStream ms = new MemoryStream();
                    file.InputStream.Position = 0;
                    file.InputStream.CopyTo(ms);
                    ms.Position = 0;

                    //Signing Process
                    string signature = utility.GenerateSignature(ms.ToArray(), privateKey);

                    // Encryption Process
                    string encryptedSK = utility.Encrypt(parameters.SecretKey, publicKey);
                    string encryptedIV = utility.Encrypt(parameters.IV, publicKey);
                    string encryptedFile = utility.Encrypt(ms.ToArray(), parameters);

                    // Storage Process
                    string filePath = Server.MapPath(@"\Files"); //File save location
                    string fileName = Guid.NewGuid().ToString(); //Generate unique file name
                    string absoluteFilePath = filePath + @"\" + fileName;

                    //Build file data, Secret key and IV in file header                 
                    utility.WriteToFile(absoluteFilePath, utility.FileMerge(encryptedSK, encryptedIV, encryptedFile));

                    //Database Process
                    article.UserId = User.Identity.GetUserId();
                    article.DateCreated = DateTime.Now;
                    article.StateId = 1;
                    article.Signature = signature;
                    article.FileName = fileName;

                    db.Articles.Add(article);
                    db.SaveChanges();

                    ViewBag.Message = "Upload & Encryption Successful";

                    return RedirectToAction("Index");
                }
                catch
                {
                    return RedirectToAction("Missing");
                }
            }
            return View();
        }

        // POST: Articles/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [Authorize(Roles = "Author, Admin")]
        [ValidateAntiForgeryToken]
        [FileCheckActionFilter]
        //[Bind(Include = "Id,UserId,ReviewId,Title,Body,DateCreated,StateId")] Article article
        public ActionResult Edit([Bind(Include = "Id,UserId,ReviewId,DateCreated,StateId,FileName,Title")] Article article, HttpPostedFileBase file)
        {
            if (ModelState.IsValid)
            {
                try {
                    if (article.StateId == 1 || article.StateId == 3) // Unlocked states
                    {
                        EncryptionUtility utility = new EncryptionUtility();
                        SymmetricParameters parameters = utility.GenerateSymmetricParameters("123qwe", "ijbygcrz");
                        string userId = User.Identity.GetUserId();
                        // Public and private keys are generated during user registration, stored in UserKey table                  
                        string PublicKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PublicKey;
                        string PrivateKey = db.UserKeys.SingleOrDefault(k => k.UserId == userId).PrivateKey;

                        //Convert file into an array of bytes, results saved in memory
                        MemoryStream ms = new MemoryStream();
                        file.InputStream.Position = 0;
                        file.InputStream.CopyTo(ms);
                        ms.Position = 0;

                        //Signing Process
                        string signature = utility.GenerateSignature(ms.ToArray(), PrivateKey);

                        // Encryption Process
                        string encryptedSK = utility.Encrypt(parameters.SecretKey, PublicKey);
                        string encryptedIV = utility.Encrypt(parameters.IV, PublicKey);
                        string encryptedFile = utility.Encrypt(ms.ToArray(), parameters);

                        // Storage Process
                        string filePath = Server.MapPath(@"\Files"); //File save location
                        string absoluteFilePath = filePath + @"\" + article.FileName;
                        // If same name of file present then delete that file first
                        if (System.IO.File.Exists(absoluteFilePath))
                        { System.IO.File.Delete(absoluteFilePath); }

                        //Build file data, Secret key and IV in file header                 
                        utility.WriteToFile(absoluteFilePath, utility.FileMerge(encryptedSK, encryptedIV, encryptedFile));

                        // Database Process
                        if (article.Review != null)
                            article.Review.Accepted = false;

                        article.StateId = 1; // Revert back to pending
                        article.DateLastEdited = DateTime.Now;
                        article.Signature = signature;

                        db.Entry(article).State = EntityState.Modified;
                        db.SaveChanges();

                        ViewBag.Message = "Upload & Encryption Successful";

                        return RedirectToAction("Index");
                    }
                    else
                    {
                        ViewBag.Message = "Only Pending or Finished articles can be updated.";
                    }
                }
                catch
                {
                    return RedirectToAction("Missing");
                }
            }

            return View(article);
        }

        [HttpPost]
        [Authorize(Roles = "Author, Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult Review(ArticleReview articleReview)
        {
            if (ModelState.IsValid)
            {
                Article currentArticle = db.Articles.SingleOrDefault(a => a.Id == articleReview.articleModel.Id);

                if (articleReview.reviewModel.Accepted)
                    currentArticle.StateId = 2; // Set as Reviewed
                else
                    currentArticle.StateId = 3; // Set as Finished           

                Review newReview = new Review();
                newReview.Comment = articleReview.reviewModel.Comment;
                newReview.Accepted = articleReview.reviewModel.Accepted;
                newReview.UserId = User.Identity.GetUserId();
                newReview.DateReviewed = DateTime.Now;

                db.Reviews.Add(newReview);

                currentArticle.ReviewId = newReview.Id;

                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(articleReview);
        }

        // POST: Articles/Review
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [Authorize(Roles = "MediaManager, Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult EditorialReview(ArticleReview articleReview)
        {
            if (ModelState.IsValid)
            {
                Article currentArticle = db.Articles.SingleOrDefault(a => a.Id == articleReview.articleModel.Id);
                Review currentReview = db.Reviews.SingleOrDefault(r => r.Id == articleReview.reviewModel.Id);

                currentArticle.StateId = 3;
                
                currentReview.DateEdited = DateTime.Now;
                currentReview.Comment = articleReview.reviewModel.Comment;
                currentReview.Accepted = articleReview.reviewModel.Accepted;
                currentReview.UserId = User.Identity.GetUserId();

                if (currentReview.Accepted && articleReview.articleModel.DatePublished != null)
                {
                    Publish publish = new Publish();
                    publish.ArticleId = currentArticle.Id;
                    publish.PublishDate = (DateTime)articleReview.articleModel.DatePublished;
                    db.Publishes.Add(publish);
                }
                else if (currentReview.Accepted && articleReview.articleModel.DatePublished == null)
                {
                    ViewBag.Message = "'Date Published' is required for Accepted articles.";
                    var tmpBind = (ArticleReview)TempData.Peek("tmpArticleReview");
                    return View(tmpBind);
                }

                db.SaveChanges();
                return RedirectToAction("PendingEditorial");
            }

            return View(articleReview);
        }

        // POST: Articles/Delete/5
        [HttpPost, ActionName("Delete")]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            Article article = db.Articles.Find(id);
            Review review = db.Articles.Find(id).Review;
            Publish publish = db.Publishes.SingleOrDefault(p => p.ArticleId == article.Id);

            if (article.StateId == 1 || article.StateId == 3)
            {
                if (review != null)
                    db.Reviews.Remove(review);

                if (publish != null)
                    db.Publishes.Remove(publish);

                string filePath = Server.MapPath(@"\Files");
                string absoluteFilePath = filePath + @"\" + article.FileName;

                //Delete file
                if (System.IO.File.Exists(absoluteFilePath))
                {
                    System.IO.File.Delete(absoluteFilePath);
                }

                db.Articles.Remove(article);
                db.SaveChanges();
            }
            else
            {
                ViewBag.Message = "Only Pending or Finished articles can be deleted.";
            }

            return RedirectToAction("Index");
        }

        #endregion

        #region Helpers
        public ActionResult BadRequest()
        {
            return View();
        }

        [Authorize(Roles = "Member")]
        public ActionResult IncorrectFormat()
        {
            return View();
        }

        [Authorize(Roles = "Member")]
        public ActionResult Missing()
        {
            return View();
        }

        [Authorize(Roles = "Member")]
        public ActionResult PublishedArticles()
        {
            IEnumerable<Article> articles = db.Articles.Where(a => a.ArticleState.Name == "Published");
            return View(articles);
        }
        #endregion
    }
}