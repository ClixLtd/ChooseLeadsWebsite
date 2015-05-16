<html>
	<head>
        <title>ChooseLeads, ChooseLeads Voice and CLV Dynamix</title>
	    <meta name="viewport" content="user-scalable=no, initial-scale=1, maximum-scale=1, minimum-scale=1, width=320, height=device-height, target-densitydpi=medium-dpi" />
	    <link href='http://fonts.googleapis.com/css?family=Roboto:100,200,400,700,500,100,300' rel='stylesheet' type='text/css'>
        <link rel="stylesheet" href="{{ elixir('css/bootstrap.css') }}">
        <link rel="stylesheet" href="{{ elixir('css/app.css') }}">
	</head>
	<body>
        <div id="overlay">
            <div id="choices">
                <a href="#" id="closeOverlay"><img src="/img/icons/close.png"></a>
                <img src="/img/choices.png" id="options">
            </div>
        </div>

        <div class="container-fluid" id="homepage-container">
        @foreach($pages as $page)
            @include( $template . '.sections.' . $page['section'], ['options' => $page['options'], 'content' => $page['content']] )
        @endforeach
        </div>


    <script src="/script/jquery.min.js"></script>
    <script type="text/javascript" src="//maps.google.com/maps/api/js?sensor=true"></script>
    <script src="/script/gmaps.min.js"></script>

    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/js/bootstrap.min.js"></script>
    <script src="//use.typekit.net/wfa7axf.js"></script>
    <script>try{Typekit.load();}catch(e){}</script>

    <script>

        function scrollToDiv(pageLink) {
            newPosition = $('#'+pageLink).offset().top - 75;

            $('html, body').animate({
                scrollTop: newPosition
            }, 500);

        }


        jQuery(document).ready(function($) {



            @if (!is_null($currentPage))
            setTimeout(function() {
                scrollToDiv("{{ $currentPage . '-container' }}");
            }, 1000);

            @endif

            $('#overlayProducts').click(function(e) {
                $('#overlay').fadeIn();
                e.preventDefault();
            });

            $('#closeOverlay').click(function(e) {
                $('#overlay').fadeOut();
                e.preventDefault();
            });

            $('.home-link').click(function(e) {
                scrollToDiv("homepage-container");
                window.history.pushState({},"", "/");
                e.preventDefault();
            });

            $(".scrollTo").click(function(e) {
                pageLink = $(this).attr('data-link');
                scrollToDiv(pageLink);
                window.history.pushState({},"", pageLink.replace('-container','').replace('#', ''));
                e.preventDefault();
            });

            $('.carousel').carousel({
                interval: 5000
            })
            var map;
            map = new GMaps({
                div: '#map',
                lat: 51.569726,
                lng: -1.825072
            });
            map.addMarker({
                lat: 51.569726,
                lng: -1.825072,
                title: 'Choose Leads'
            });

            $('#menuShower').click(function(e) {
                $('#mobileMenu').slideToggle();
                e.preventDefault();
            });
        });
    </script>
	</body>
</html>
