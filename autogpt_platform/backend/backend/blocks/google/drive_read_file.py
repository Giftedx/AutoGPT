from typing import Literal, Optional

from backend.blocks.base import Block, BlockSchema, CredentialsMetaInput, ProviderName
from backend.models.credentials import OAuth2Credentials


class GoogleDriveReadFileBlockInput(BlockSchema):
    credentials: CredentialsMetaInput[
        Literal[ProviderName.GOOGLE], Literal["oauth2"]
    ] = CredentialsMetaInput(
        provider_name=ProviderName.GOOGLE,
        credentials_type="oauth2",
        scopes=["https://www.googleapis.com/auth/drive.readonly"],
    )
    file_id: str
    mime_type_preference: Optional[str] = None


class GoogleDriveReadFileBlockOutput(BlockSchema):
    file_content: str
    file_name: str
    error: Optional[str] = None


class GoogleDriveReadFileBlock(Block):
    def __init__(self):
        super().__init__(
            id="google-drive-read-file-block-uuid",  # Placeholder for a real UUID
            input_schema=GoogleDriveReadFileBlockInput,
            output_schema=GoogleDriveReadFileBlockOutput,
            test_input={"file_id": "test_file_id"},
            test_output=[
                ("file_content", "mock content"),
                ("file_name", "test_file.txt"),
            ],
            test_mock=self._test_mock,
            test_credentials=OAuth2Credentials(
                provider_name=ProviderName.GOOGLE,
                access_token="mock_access_token",
                refresh_token="mock_refresh_token",
                expires_at=0,  # A non-None value, can be expired
                scopes=["https://www.googleapis.com/auth/drive.readonly"],
            ),
        )

    @staticmethod
    def _test_mock(mock_service_builder):
        mock_service = mock_service_builder.return_value
        mock_files = mock_service.files.return_value

        # Mock for metadata call
        mock_get = mock_files.get.return_value
        mock_get.execute.return_value = {
            "name": "test_file.txt",
            "mimeType": "text/plain",  # Default to non-Google Workspace type
        }

        # Mock for content call (get_media)
        mock_get_media = mock_files.get_media.return_value
        mock_get_media.execute.return_value = b"mock content"

        # Mock for content call (export_media) - in case mimeType changes
        mock_export_media = mock_files.export_media.return_value
        mock_export_media.execute.return_value = b"mock content for export"

        return mock_service_builder

    def run(self, input_data: GoogleDriveReadFileBlockInput, credentials: OAuth2Credentials):
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError

        try:
            # TODO: Consider how to handle token expiry and refresh if the library doesn't do it.
            # For now, assume credentials are valid or the google client library handles refresh.
            google_creds_for_client = credentials.to_google_credentials()

            service = build("drive", "v3", credentials=google_creds_for_client)

            # Fetch file metadata
            file_metadata = (
                service.files()
                .get(fileId=input_data.file_id, fields="name, mimeType")
                .execute()
            )
            file_name = file_metadata.get("name")
            file_mime_type = file_metadata.get("mimeType")

            google_workspace_mime_types = [
                "application/vnd.google-apps.document",
                "application/vnd.google-apps.spreadsheet",
                "application/vnd.google-apps.presentation",
            ]

            content_bytes = b""
            if file_mime_type in google_workspace_mime_types:
                # Determine the export MIME type
                # For simplicity, using a predefined mapping or allowing preference
                export_mime_type = input_data.mime_type_preference
                if not export_mime_type:
                    if file_mime_type == "application/vnd.google-apps.document":
                        export_mime_type = "text/plain"  # Or application/pdf, etc.
                    elif file_mime_type == "application/vnd.google-apps.spreadsheet":
                        export_mime_type = "text/csv"  # Or application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
                    elif file_mime_type == "application/vnd.google-apps.presentation":
                        export_mime_type = "application/pdf" # Or text/plain for notes
                    else:
                        # Fallback, though should be covered by above
                        export_mime_type = "text/plain"

                content_bytes = (
                    service.files()
                    .export_media(
                        fileId=input_data.file_id, mimeType=export_mime_type
                    )
                    .execute()
                )
            else:
                content_bytes = (
                    service.files().get_media(fileId=input_data.file_id).execute()
                )

            # Assuming text content for now. For binary, this would need adjustment.
            try:
                content_str = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # If it's not UTF-8, we might need to handle it differently
                # or indicate that it's binary content. For now, yield an error.
                yield ("error", f"Could not decode file content as UTF-8. File might be binary or use a different encoding.")
                return


            yield ("file_content", content_str)
            yield ("file_name", file_name)

        except HttpError as e:
            yield ("error", f"Google API HTTP error: {e.resp.status} {e.reason} - {e.content.decode()}")
        except Exception as e:
            # Catch any other unexpected errors
            yield ("error", f"An unexpected error occurred: {str(e)}")
