using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace BennetVellaSecureSoftware.Models
{
    public class ArticleReview
    {
        public Article articleModel { get; set; }
        public Review reviewModel { get; set; }
    }
}