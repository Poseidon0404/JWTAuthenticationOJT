using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWTAuthenticationOJT.Migrations
{
    /// <inheritdoc />
    public partial class AddBiometricColumnsToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "HasBiometric",
                table: "AspNetUsers",
                newName: "UseFingerprint");

            migrationBuilder.AddColumn<bool>(
                name: "UseFaceId",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UseFaceId",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "UseFingerprint",
                table: "AspNetUsers",
                newName: "HasBiometric");
        }
    }
}
