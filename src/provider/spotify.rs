use async_graphql::{Enum};
use nitroglycerin::serde::{Serialize, Deserialize};

pub struct SpotifyProvider;

impl super::Provider for SpotifyProvider {
    const AUTH_URL: &'static str = "https://accounts.spotify.com/authorize";
    const TOKEN_URL: &'static str = "https://accounts.spotify.com/api/token";

    type Scopes = SpotifyScope;
}



#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpotifyScope {
    UgcImageUpload,
    UserReadRecentlyPlayed,
    UserTopRead,
    UserReadPlaybackPosition,
    UserReadPlaybackState,
    UserModifyPlaybackState,
    UserReadCurrentlyPlaying,
    AppRemoteControl,
    Streaming,
    PlaylistModifyPublic,
    PlaylistModifyPrivate,
    PlaylistReadPrivate,
    PlaylistReadCollaborative,
    UserFollowModify,
    UserFollowRead,
    UserLibraryModify,
    UserLibraryRead,
    UserReadEmail,
    UserReadPrivate,
}

impl super::ProviderScopes for SpotifyScope {
    fn to_str(&self) -> &'static str {
        match self {
            Self::UgcImageUpload => "ugc-image-upload",
            Self::UserReadRecentlyPlayed => "user-read-recently-played",
            Self::UserTopRead => "user-top-read",
            Self::UserReadPlaybackPosition => "user-read-playback-position",
            Self::UserReadPlaybackState => "user-read-playback-state",
            Self::UserModifyPlaybackState => "user-modify-playback-state",
            Self::UserReadCurrentlyPlaying => "user-read-currently-playing",
            Self::AppRemoteControl => "app-remote-control",
            Self::Streaming => "streaming",
            Self::PlaylistModifyPublic => "playlist-modify-public",
            Self::PlaylistModifyPrivate => "playlist-modify-private",
            Self::PlaylistReadPrivate => "playlist-read-private",
            Self::PlaylistReadCollaborative => "playlist-read-collaborative",
            Self::UserFollowModify => "user-follow-modify",
            Self::UserFollowRead => "user-follow-read",
            Self::UserLibraryModify => "user-library-modify",
            Self::UserLibraryRead => "user-library-read",
            Self::UserReadEmail => "user-read-email",
            Self::UserReadPrivate => "user-read-private",
        }
    }
}
