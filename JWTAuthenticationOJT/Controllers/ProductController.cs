using JWTAuthenticationOJT.Auth;
using JWTAuthenticationOJT.Dtos;
using JWTAuthenticationOJT.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Bogus;

namespace JWTAuthenticationOJT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public ProductController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Product
        [HttpGet]
        public async Task<ActionResult<IEnumerable<ProductDto>>> GetProducts()
        {
            return await _context.Products
                .Select(p => new ProductDto
                {
                    Id = p.Id,
                    CategoryId = p.CategoryId,
                    Name = p.Name,
                    Description = p.Description,
                    Status = p.Status
                }).ToListAsync();
        }

        // GET: api/Product/5
        [HttpGet("{id}")]
        public async Task<ActionResult<ProductDto>> GetProduct(int id)
        {
            var product = await _context.Products.FindAsync(id);
            if (product == null) return NotFound();

            return new ProductDto
            {
                Id = product.Id,
                CategoryId = product.CategoryId,
                Name = product.Name,
                Description = product.Description,
                Status = product.Status
            };
        }

        // POST: api/Product
        [HttpPost("create")]
        public async Task<ActionResult<ProductDto>> PostProduct(ProductDto dto)
        {
            var product = new Product
            {
                CategoryId = dto.CategoryId,
                Name = dto.Name,
                Description = dto.Description,
                Status = dto.Status
            };

            _context.Products.Add(product);
            await _context.SaveChangesAsync();

            dto.Id = product.Id;
            return CreatedAtAction(nameof(GetProduct), new { id = dto.Id }, dto);
        }

        // PUT: api/Product/5
        [HttpPut("update/{id}")]
        public async Task<IActionResult> PutProduct(int id, ProductDto dto)
        {
            if (id != dto.Id) return BadRequest();

            var product = await _context.Products.FindAsync(id);
            if (product == null) return NotFound();

            product.CategoryId = dto.CategoryId;
            product.Name = dto.Name;
            product.Description = dto.Description;
            product.Status = dto.Status;

            await _context.SaveChangesAsync();
            return NoContent();
        }

        // DELETE: api/Product/5
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteProduct(int id)
        {
            var product = await _context.Products.FindAsync(id);
            if (product == null) return NotFound();

            _context.Products.Remove(product);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        //adding a products
        [HttpPost("seed/{count}")]
        public async Task<IActionResult> SeedProducts(int count = 500)
        {
            // Ensure categories exist
            var categoryIds = await _context.Categories.Select(c => c.Id).ToListAsync();
            if (!categoryIds.Any())
            {
                return BadRequest("Please seed categories first before products.");
            }

            var faker = new Bogus.Faker<Product>()
                .RuleFor(p => p.CategoryId, f => f.PickRandom(categoryIds))
                .RuleFor(p => p.Name, f => f.Commerce.ProductName())
                .RuleFor(p => p.Description, f => f.Commerce.ProductDescription())
                .RuleFor(p => p.Status, f => true);


            var fakeProducts = faker.Generate(count);

            _context.Products.AddRange(fakeProducts);
            await _context.SaveChangesAsync();

            return Ok($"{count} products generated successfully!");
        }

        // removing/deleting a products

        [HttpDelete("remove/{count}")]
        public async Task<IActionResult> DeleteProducts(int count = 100)
        {
            var products = await _context.Products
                .OrderByDescending(p => p.Id)   
                .Take(count)
                .ToListAsync();

            if (!products.Any())
            {
                return NotFound("No products available to delete.");
            }

            _context.Products.RemoveRange(products);
            await _context.SaveChangesAsync();

            return Ok($"{products.Count} products deleted successfully!");
        }

    }
}
