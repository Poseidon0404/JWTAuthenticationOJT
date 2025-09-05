namespace JWTAuthenticationOJT.Models
{
    public class Product
    {
        public int Id { get; set; }
        public int CategoryId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool Status { get; set; }

        // Navigation
        public Category? Category { get; set; }
    }
}
