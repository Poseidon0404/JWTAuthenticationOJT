using Bogus;
using JWTAuthenticationOJT.Auth;
using JWTAuthenticationOJT.Dtos;
using JWTAuthenticationOJT.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthenticationOJT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CategoryController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CategoryController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Category
        [HttpGet]
        public async Task<ActionResult<IEnumerable<CategoryDto>>> GetCategories()
        {
            return await _context.Categories
                .Select(c => new CategoryDto { Id = c.Id, Name = c.Name })
                .ToListAsync();
        }

        // GET: api/Category/5
        [HttpGet("{id}")]
        public async Task<ActionResult<CategoryDto>> GetCategory(int id)
        {
            var category = await _context.Categories.FindAsync(id);
            if (category == null) return NotFound();

            return new CategoryDto { Id = category.Id, Name = category.Name };
        }

        // POST: api/Category
        [HttpPost("create")]

        public async Task<ActionResult<CategoryDto>> PostCategory(CategoryDto dto)
        {
            var category = new Category { Name = dto.Name };
            _context.Categories.Add(category);
            await _context.SaveChangesAsync();

            dto.Id = category.Id;
            return CreatedAtAction(nameof(GetCategory), new { id = dto.Id }, dto);
        }

        // PUT: api/Category/5
        [HttpPut("update/{id}")]
        public async Task<IActionResult> PutCategory(int id, CategoryDto dto)
        {
            if (id != dto.Id) return BadRequest();

            var category = await _context.Categories.FindAsync(id);
            if (category == null) return NotFound();

            category.Name = dto.Name;
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // DELETE: api/Category/5
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteCategory(int id)
        {
            var category = await _context.Categories.FindAsync(id);
            if (category == null) return NotFound();

            _context.Categories.Remove(category);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // adding a category
        [HttpPost("seed/{count}")]
        public async Task<IActionResult> SeedCategories(int count = 500)
        {
            var faker = new Faker<Category>()
                .RuleFor(c => c.Name, f => f.Commerce.Categories(1)[0]);

            var fakeCategories = faker.Generate(count);

            _context.Categories.AddRange(fakeCategories);
            await _context.SaveChangesAsync();

            return Ok($"{count} categories generated successfully!");
        }

        // deleting a category
        [HttpDelete("remove/{count}")]
        public async Task<IActionResult> DeleteCategories(int count = 100)
        {
            var categories = await _context.Categories
                .OrderByDescending(c => c.Id)   // delete newest first
                .Take(count)
                .ToListAsync();

            if (!categories.Any())
            {
                return NotFound("No categories available to delete.");
            }

            _context.Categories.RemoveRange(categories);
            await _context.SaveChangesAsync();

            return Ok($"{categories.Count} categories deleted successfully!");
        }

    }
}
