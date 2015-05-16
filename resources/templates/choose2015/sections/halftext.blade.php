<div class="col-md-12" id="{{ $options['sectionId'] }}-container">

    <div class="container" id="{{ $options['sectionId'] }}">

        <div class="text-center col-lg-{{ $options['size'] }} {{ $options['position'] == 'left' ?: 'col-lg-offset-'.(12-$options['size']) }}">
            {!! isset($content['content-1']) ? $content['content-1'] : "" !!}

            <p>
                <button type="button" data-link="contactus-container" class="scrollTo btn btn-default btn-lg">
                    <span class="glyphicon glyphicon-envelope" aria-hidden="true"></span> Get In Touch
                </button>
            </p>
        </div>


    </div>

</div>
