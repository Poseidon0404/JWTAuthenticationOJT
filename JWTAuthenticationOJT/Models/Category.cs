namespace JWTAuthenticationOJT.Models
{
    public class Category
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;

        // Navigation
        public ICollection<Product>? Products { get; set; }
    }

}
