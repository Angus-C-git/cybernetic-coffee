
function twitterFeed() {
    document.getElementById('feed').innerHTML = '';

    const loader = document.getElementById('loader');
    loader.innerHTML = "<span id=\"loader\"><i class=\"fas fa-spinner\"></i> Loading ...</span>";

    let nonSelected = document.getElementById('github');
    nonSelected.classList.remove('feed-selected');
    nonSelected.classList.add('feed-non-selected');

    let selected = document.getElementById('twitter');
    selected.classList.remove('feed-non-selected');
    selected.classList.add('feed-selected');

    let requestOptions = {
        method: 'GET',
        redirect: 'follow'
    };

    fetch("https://cybernetic-coffee-api.herokuapp.com/api/tweets", requestOptions)
        .then(response => response.json())
        .then(result => {
            let feed = document.getElementById("feed");
            feed.innerHTML = '';
            loader.innerHTML = '';

            result.map(tweet => {
                let icon = (tweet.text.indexOf('RT') >= 0) ? `<i class="fas fa-retweet"></i>` : `<i class="fab fa-twitter">`;
                feed.innerHTML += `<li class="timeline-event">
                                        <label class="timeline-event-icon"></label>
                                        <div class="timeline-event-copy">
                                            <p class="timeline-event-thumbnail">${tweet.created_at.slice(0, 16)}</p>
                                            <h3>${icon}</i> <a class="repo" href="https://twitter.com/ghostinthefiber/status/${tweet.id_str}" target="_blank">by ghostinthefiber</a></h3>
                                            <p>${tweet.text}</p>
                                        </div>
                                    </li>`
            });
        })
        .catch(error => console.log('error', error));
}


function expand_challenge(card) {
    card.innerHTML = (card.id === "") ? "<i class=\"fas fa-chevron-up fa-lg\"></i>" : "<i class=\"fas fa-chevron-down fa-lg\"></i>"
    card.id = (card.id === "active") ? "" : "active";

    // TODO: Fix this pain :C
    if (card.id === "active") {
        card.parentElement.children[3].classList.remove("collapse-aoe");
        card.parentElement.children[4].classList.remove("collapse-aoe");
        card.parentElement.children[5].classList.remove("collapse-aoe");
        card.parentElement.children[6].classList.remove("collapse-aoe");
    } else {
        card.parentElement.children[3].classList.add("collapse-aoe");
        card.parentElement.children[4].classList.add("collapse-aoe");
        card.parentElement.children[5].classList.add("collapse-aoe");
        card.parentElement.children[6].classList.add("collapse-aoe");
    }




}
